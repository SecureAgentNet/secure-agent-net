import secrets
import jwt
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
from typing import Optional


def generate_nonce() -> str:
    """Generates a secure 32-byte hexadecimal random string."""
    return secrets.token_hex(32)


def generate_session_id() -> str:
    """Generates a secure session identifier."""
    return secrets.token_urlsafe(16)


def verify_signature(public_key_pem: str, nonce: str, signature_hex: str) -> bool:
    """
    Verifies that the given nonce was signed by the private key 
    corresponding to the provided public_key_pem.
    Supports RSA and EC keys.
    """
    try:
        public_key = load_pem_public_key(public_key_pem.encode('utf-8'))
        signature_bytes = bytes.fromhex(signature_hex)
        nonce_bytes = nonce.encode('utf-8')

        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature_bytes,
                nonce_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                signature_bytes,
                nonce_bytes,
                ec.ECDSA(hashes.SHA256())
            )
        else:
            return False
            
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def create_access_token(data: dict, secret_key: str, algorithm: str, expires_delta: Optional[timedelta] = None) -> str:
    """Generates a JWT access token for the authenticated agent."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=60)
        
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, secret_key, algorithm=algorithm)
    return encoded_jwt


def decode_access_token(token: str, secret_key: str, algorithm: str) -> Optional[dict]:
    """Decodes and validates a JWT access token. Returns payload or None."""
    try:
        payload = jwt.decode(token, secret_key, algorithms=[algorithm])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
