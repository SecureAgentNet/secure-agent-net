import secrets
import jwt
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    load_pem_public_key, load_pem_private_key,
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
)
from cryptography.exceptions import InvalidSignature
from typing import Optional, Tuple


def generate_nonce() -> str:
    """Generates a secure 32-byte hexadecimal random string."""
    return secrets.token_hex(32)


def generate_session_id() -> str:
    """Generates a secure session identifier."""
    return secrets.token_urlsafe(16)


def generate_ed25519_keypair() -> Tuple[str, str]:
    """Generates an Ed25519 keypair, returned as (private_pem, public_pem).

    Ed25519 is the trust-anchor and manifest-signing algorithm for SecureAgentNet:
    small keys, fast verification, and no parameter-choice footguns.
    """
    priv = Ed25519PrivateKey.generate()
    private_pem = priv.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    ).decode("utf-8")
    public_pem = priv.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    return private_pem, public_pem


def sign_message(private_key_pem: str, message: bytes) -> str:
    """Signs an arbitrary byte message with a PEM private key (Ed25519/EC/RSA).

    Returns the signature as a hex string. Used to sign agent manifests with the
    trust authority's root key.
    """
    key = load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    if isinstance(key, Ed25519PrivateKey):
        signature = key.sign(message)
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        signature = key.sign(message, ec.ECDSA(hashes.SHA256()))
    elif isinstance(key, rsa.RSAPrivateKey):
        signature = key.sign(
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    else:
        raise ValueError("Unsupported private key type for signing")
    return signature.hex()


def verify_message(public_key_pem: str, message: bytes, signature_hex: str) -> bool:
    """Verifies a byte message against a signature using a PEM public key.

    Supports Ed25519, EC (ECDSA/SHA-256) and RSA (PSS/SHA-256).
    """
    try:
        public_key = load_pem_public_key(public_key_pem.encode("utf-8"))
        signature_bytes = bytes.fromhex(signature_hex)

        if isinstance(public_key, Ed25519PublicKey):
            public_key.verify(signature_bytes, message)
        elif isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature_bytes,
                message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature_bytes, message, ec.ECDSA(hashes.SHA256()))
        else:
            return False
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def verify_signature(public_key_pem: str, nonce: str, signature_hex: str) -> bool:
    """
    Verifies that the given nonce was signed by the private key
    corresponding to the provided public_key_pem.
    Supports Ed25519, EC and RSA keys.
    """
    return verify_message(public_key_pem, nonce.encode("utf-8"), signature_hex)


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
