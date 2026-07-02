import tempfile
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
import jwt
import yaml

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

from secureagentnet.client import SecureAgentClient, SecureRuntimeWrapper


@pytest.fixture
def rsa_keys():
    """Generates a transient RSA private and public key pair in PEM format."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    ).decode("utf-8")
    
    public_pem = private_key.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    
    return private_pem, public_pem


@pytest.fixture
def ec_keys():
    """Generates a transient Elliptic Curve private and public key pair in PEM format."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    ).decode("utf-8")
    
    public_pem = private_key.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    
    return private_pem, public_pem


class TestSecureAgentClient:

    def test_client_initialization_rsa(self, rsa_keys):
        private_pem, _ = rsa_keys
        client = SecureAgentClient(
            gateway_url="http://localhost:5000",
            agent_id="test-agent",
            private_key_pem=private_pem
        )
        assert client.gateway_url == "http://localhost:5000"
        assert client.agent_id == "test-agent"
        assert isinstance(client.private_key, rsa.RSAPrivateKey)

    def test_client_initialization_ec(self, ec_keys):
        private_pem, _ = ec_keys
        client = SecureAgentClient(
            gateway_url="http://localhost:5000",
            agent_id="test-agent",
            private_key_pem=private_pem
        )
        assert isinstance(client.private_key, ec.EllipticCurvePrivateKey)

    def test_client_initialization_invalid_key(self):
        with pytest.raises(ValueError, match="Invalid private key PEM"):
            SecureAgentClient(
                gateway_url="http://localhost:5000",
                agent_id="test-agent",
                private_key_pem="NOT-A-PEM-KEY"
            )

    def test_sign_nonce_rsa(self, rsa_keys):
        private_pem, public_pem = rsa_keys
        client = SecureAgentClient(
            gateway_url="http://localhost:5000",
            agent_id="test-agent",
            private_key_pem=private_pem
        )
        nonce = "abc123nonce"
        sig_hex = client._sign_nonce(nonce)
        assert len(sig_hex) > 0
        
        # Verify the signature matches expectations using cryptography RSAPublicKey verify
        from secureagentnet.utils.crypto import verify_signature
        assert verify_signature(public_pem, nonce, sig_hex) is True

    def test_sign_nonce_ec(self, ec_keys):
        private_pem, public_pem = ec_keys
        client = SecureAgentClient(
            gateway_url="http://localhost:5000",
            agent_id="test-agent",
            private_key_pem=private_pem
        )
        nonce = "abc123nonce"
        sig_hex = client._sign_nonce(nonce)
        assert len(sig_hex) > 0
        
        # Verify using ec EllipticCurvePublicKey verify
        from secureagentnet.utils.crypto import verify_signature
        assert verify_signature(public_pem, nonce, sig_hex) is True

    @patch("requests.post")
    def test_login_flow_success(self, mock_post, rsa_keys):
        private_pem, _ = rsa_keys
        
        # Mock responses: Challenge and Login
        mock_challenge_resp = MagicMock()
        mock_challenge_resp.status_code = 200
        mock_challenge_resp.json.return_value = {
            "nonce": "testnonce123",
            "session_id": "testsession456"
        }
        
        # Generate dummy token
        dummy_token = jwt.encode(
            {"sub": "test-agent", "exp": int(time.time()) + 3600},
            "secret",
            algorithm="HS256"
        )
        
        mock_login_resp = MagicMock()
        mock_login_resp.status_code = 200
        mock_login_resp.json.return_value = {
            "access_token": dummy_token,
            "expires_in": 3600
        }
        
        mock_post.side_effect = [mock_challenge_resp, mock_login_resp]
        
        client = SecureAgentClient(
            gateway_url="http://localhost:5000",
            agent_id="test-agent",
            private_key_pem=private_pem
        )
        
        token = client.login()
        assert token == dummy_token
        assert client.token == dummy_token
        assert client.token_expiry > time.time()
        assert mock_post.call_count == 2

    @patch("requests.post")
    def test_execute_tool_success(self, mock_post, rsa_keys):
        private_pem, _ = rsa_keys
        
        # Initialize client with an already active token
        client = SecureAgentClient(
            gateway_url="http://localhost:5000",
            agent_id="test-agent",
            private_key_pem=private_pem
        )
        client.token = "active-jwt-token"
        client.token_expiry = time.time() + 600
        
        # Mock Execute response
        mock_exec_resp = MagicMock()
        mock_exec_resp.status_code = 200
        mock_exec_resp.json.return_value = {
            "status": "allowed",
            "exit_code": 0,
            "stdout": "execution output",
            "stderr": ""
        }
        mock_post.return_value = mock_exec_resp
        
        res = client.execute_tool(
            action_name="execute",
            target_resource="shell",
            command="echo 'hello'",
            intent_summary="test intent"
        )
        
        assert res["status"] == "allowed"
        assert res["stdout"] == "execution output"
        
        # Check API parameters passed
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert args[0] == "http://localhost:5000/api/v1/mcp/execute"
        assert kwargs["json"]["action_name"] == "execute"
        assert kwargs["json"]["payload"]["command"] == "echo 'hello'"
        assert kwargs["headers"]["Authorization"] == "Bearer active-jwt-token"


class TestSecureRuntimeWrapper:

    def test_wrapper_default_load(self):
        # Instantiate without file should fallback gracefully
        wrapper = SecureRuntimeWrapper(config_path="non-existent.yaml")
        assert wrapper.client is not None
        assert wrapper.client.gateway_url == "http://localhost:5000"
        assert wrapper.client.agent_id == "agent-007"

    def test_wrapper_load_yaml(self, rsa_keys):
        private_pem, _ = rsa_keys
        
        # Write config and key files
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "agent_key.pem"
            key_path.write_text(private_pem)
            
            yaml_path = Path(tmpdir) / "secureagentnet.yaml"
            config_data = {
                "gateway": {
                    "url": "http://remote-gateway:8443",
                    "agent_id": "agent-xyz",
                    "private_key_path": str(key_path)
                }
            }
            with open(yaml_path, "w") as f:
                yaml.dump(config_data, f)
                
            wrapper = SecureRuntimeWrapper(config_path=str(yaml_path))
            assert wrapper.client is not None
            assert wrapper.client.gateway_url == "http://remote-gateway:8443"
            assert wrapper.client.agent_id == "agent-xyz"
            assert wrapper.client.private_key_pem == private_pem

    def test_wrap_tool_execution(self, ec_keys):
        private_pem, _ = ec_keys
        wrapper = SecureRuntimeWrapper(config_path="non-existent.yaml")
        wrapper.client = SecureAgentClient(
            gateway_url="http://localhost:5000",
            agent_id="test-agent",
            private_key_pem=private_pem
        )
        wrapper.client.token = "token"
        wrapper.client.token_expiry = time.time() + 600

        # Define dummy tool
        def dummy_terminal(cmd: str):
            """Test tool function."""
            return cmd

        wrapped = wrapper.wrap_tool(dummy_terminal)
        
        # Mock execution success
        mock_exec_resp = {
            "status": "allowed",
            "exit_code": 0,
            "stdout": "hello output",
            "stderr": ""
        }
        
        with patch.object(wrapper.client, "execute_tool", return_value=mock_exec_resp) as mock_exec:
            res = wrapped("echo 'hello'", verbose=True)
            assert res == "hello output"
            mock_exec.assert_called_once_with(
                action_name="execute",
                target_resource="shell",
                command="echo 'hello' --verbose=True",
                intent_summary="Agent invoking wrapped tool: dummy_terminal",
                payload={"args": ("echo 'hello'",), "kwargs": {"verbose": True}}
            )
