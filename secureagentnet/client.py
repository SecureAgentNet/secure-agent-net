import logging
import os
import time
from pathlib import Path
from typing import Dict, Optional, Any, Callable
import yaml
import requests
import jwt

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger("SecureAgentNet.Client")


class SecureAgentClient:
    """
    Client SDK for authenticating and executing tools securely 
    through a remote SecureAgentNet Gateway.
    """

    def __init__(
        self,
        gateway_url: str,
        agent_id: str,
        private_key_pem: str,
    ):
        self.gateway_url = gateway_url.rstrip("/")
        self.agent_id = agent_id
        self.private_key_pem = private_key_pem
        self.token: Optional[str] = None
        self.token_expiry: float = 0.0

        # Load private key eagerly to validate formats
        try:
            self.private_key = load_pem_private_key(
                self.private_key_pem.encode("utf-8"),
                password=None
            )
        except Exception as e:
            raise ValueError(f"Invalid private key PEM: {e}")

    def _sign_nonce(self, nonce: str) -> str:
        """Signs a challenge nonce using RSA or ECDSA private key algorithms."""
        nonce_bytes = nonce.encode("utf-8")
        if isinstance(self.private_key, rsa.RSAPrivateKey):
            signature = self.private_key.sign(
                nonce_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        elif isinstance(self.private_key, ec.EllipticCurvePrivateKey):
            signature = self.private_key.sign(
                nonce_bytes,
                ec.ECDSA(hashes.SHA256())
            )
        else:
            raise TypeError("Unsupported private key type. Must be RSA or Elliptic Curve (EC).")
        return signature.hex()

    def login(self) -> str:
        """
        Performs the cryptographic handshake (challenge-response) 
        with the gateway and returns a JWT access token.
        """
        # Step 1: Request Challenge
        challenge_url = f"{self.gateway_url}/api/v1/auth/challenge"
        # Extract public key format or just supply key representation
        # For simplicity, pass the key PEM
        # Wait: The challenge expects the public key PEM in the request
        # Let's derive public key PEM from private key
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        pub_key_pem = self.private_key.public_key().public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

        response = requests.post(
            challenge_url,
            json={"public_key": pub_key_pem},
            timeout=10
        )
        if response.status_code != 200:
            raise RuntimeError(f"Authentication challenge failed: {response.text}")

        challenge_data = response.json()
        nonce = challenge_data["nonce"]
        session_id = challenge_data["session_id"]

        # Step 2: Sign challenge nonce
        signature = self._sign_nonce(nonce)

        # Step 3: Login to verify and fetch JWT
        login_url = f"{self.gateway_url}/api/v1/auth/login"
        login_response = requests.post(
            login_url,
            json={"session_id": session_id, "signature": signature},
            timeout=10
        )
        if login_response.status_code != 200:
            raise RuntimeError(f"Cryptographic verification failed: {login_response.text}")

        token_data = login_response.json()
        self.token = token_data["access_token"]
        
        # Decode token to check expiration (without signature validation on client side)
        try:
            payload = jwt.decode(self.token, options={"verify_signature": False})
            self.token_expiry = payload.get("exp", time.time() + 3600)
        except Exception:
            self.token_expiry = time.time() + token_data.get("expires_in", 3600)

        logger.info("Successfully authenticated with SecureAgentNet Gateway.")
        return self.token

    def _ensure_authenticated(self):
        """Checks token expiration and logs in automatically if required."""
        # Buffer of 30 seconds
        if not self.token or time.time() >= (self.token_expiry - 30):
            self.login()

    def execute_tool(
        self,
        action_name: str,
        target_resource: str,
        command: str,
        intent_summary: str = "",
        payload: Optional[Dict[str, Any]] = None,
        files: Optional[list] = None,
    ) -> Dict[str, Any]:
        """
        Sends tool execution requests to the remote gateway's MCP execute API.

        ``files`` optionally carries input files (each a dict with ``path`` and
        ``content_base64``) into the sandbox workspace before the command runs.
        """
        self._ensure_authenticated()

        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }

        body = {
            "action_name": action_name,
            "target_resource": target_resource,
            "intent_summary": intent_summary,
            "payload": payload or {},
            "files": files or [],
        }
        # In MCP, we also map parameters to payload
        if "command" not in body["payload"]:
            body["payload"]["command"] = command

        execute_url = f"{self.gateway_url}/api/v1/mcp/execute"
        try:
            response = requests.post(execute_url, json=body, headers=headers, timeout=60)
            if response.status_code == 401:
                # Force re-authentication once if token expired
                self.login()
                headers["Authorization"] = f"Bearer {self.token}"
                response = requests.post(execute_url, json=body, headers=headers, timeout=60)

            if response.status_code != 200:
                logger.error("Gateway execution returned error %d: %s", response.status_code, response.text)
                return {
                    "status": "error",
                    "error": f"Gateway error: {response.text}",
                    "exit_code": -1,
                    "stdout": "",
                    "stderr": response.text
                }
            return response.json()
        except requests.RequestException as e:
            logger.exception("Failed to connect to gateway execution endpoint")
            return {
                "status": "error",
                "error": f"Gateway connection error: {e}",
                "exit_code": -1,
                "stdout": "",
                "stderr": str(e)
            }


class SecureRuntimeWrapper:
    """
    Wrapper for wrapping standard agent tools and parsing configuration files.
    """

    def __init__(self, config_path: str = "./secureagentnet.yaml"):
        self.config_path = Path(config_path)
        self.client: Optional[SecureAgentClient] = None
        self.load_config()

    def load_config(self):
        """Loads configuration from YAML file or environment variables."""
        gateway_url = os.environ.get("SECURE_GATEWAY_URL")
        agent_id = os.environ.get("SECURE_AGENT_ID")
        private_key_path = os.environ.get("SECURE_PRIVATE_KEY_PATH")
        private_key_pem = os.environ.get("SECURE_PRIVATE_KEY")

        if self.config_path.exists():
            try:
                with open(self.config_path) as f:
                    config = yaml.safe_load(f) or {}
                
                gateway_config = config.get("gateway", {})
                if not gateway_url:
                    gateway_url = gateway_config.get("url")
                if not agent_id:
                    agent_id = gateway_config.get("agent_id")
                if not private_key_path:
                    private_key_path = gateway_config.get("private_key_path")
            except Exception as e:
                logger.warning("Failed to parse config YAML: %s", e)

        # Resolve private key PEM content
        if not private_key_pem and private_key_path:
            p = Path(private_key_path)
            if p.exists():
                private_key_pem = p.read_text("utf-8")

        # Fallbacks to default localhost sandbox settings for testing/dev
        if not gateway_url:
            gateway_url = "http://localhost:5000"
        if not agent_id:
            agent_id = "agent-007"
        
        # If no key provided, generate a temporary developer EC key to avoid crashes
        if not private_key_pem:
            logger.warning("No private key provided. Creating a transient key for testing.")
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
            temp_key = ec.generate_private_key(ec.SECP256R1())
            private_key_pem = temp_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            ).decode("utf-8")

        self.client = SecureAgentClient(
            gateway_url=gateway_url,
            agent_id=agent_id,
            private_key_pem=private_key_pem
        )

    def wrap_tool(
        self,
        tool_func: Callable[..., Any],
        action_name: str = "execute",
        target_resource: str = "shell",
        intent_summary: str = ""
    ) -> Callable[..., Any]:
        """
        Wraps a function and delegates execution to the remote gateway.
        """
        def secure_tool_wrapper(*args, **kwargs) -> Any:
            # Reconstruct the tool arguments as a shell command or payload parameter
            command_args = []
            for arg in args:
                command_args.append(str(arg))
            for k, v in kwargs.items():
                command_args.append(f"--{k}={v}")
                
            cmd = " ".join(command_args)
            if not cmd and hasattr(tool_func, "__name__"):
                cmd = tool_func.__name__

            logger.info("Routing tool '%s' execution to SecureAgentNet...", tool_func.__name__)
            res = self.client.execute_tool(
                action_name=action_name,
                target_resource=target_resource,
                command=cmd,
                intent_summary=intent_summary or f"Agent invoking wrapped tool: {tool_func.__name__}",
                payload={"args": args, "kwargs": kwargs}
            )

            # Return tool outputs or error details
            if res.get("status") == "blocked":
                return f"Blocked by SecureAgentNet policy: {res.get('reason') or res.get('stderr') or 'Denial'}"
            
            if res.get("status") == "escalated":
                return f"Escalated to human review: {res.get('reason') or 'Pending approval'}"

            # Check if there is a 'data' dict (actual gateway format) or direct stdout (mock/test format)
            data = res.get("data")
            if isinstance(data, dict):
                stdout = data.get("stdout")
                stderr = data.get("stderr")
            else:
                stdout = res.get("stdout")
                stderr = res.get("stderr")

            return stdout or stderr or ""

        # Maintain docstring and names
        if hasattr(tool_func, "__name__"):
            secure_tool_wrapper.__name__ = tool_func.__name__
        if hasattr(tool_func, "__doc__") and tool_func.__doc__:
            secure_tool_wrapper.__doc__ = tool_func.__doc__

        return secure_tool_wrapper
