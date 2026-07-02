"""Cryptographic trust chain for MCP-registered agents (Deliverable 3).

This is the IDENTIFY-layer counterpart to challenge-response authentication. Where
authentication proves an agent *controls* a private key right now, the trust chain
proves that key — and the agent's declared capabilities and vetted tool set — were
*vouched for* by the SecureAgentNet trust authority at registration time.

The chain has two links:

    SAN Root Authority  --signs-->  Agent Manifest  --binds-->  Agent public key
       (Ed25519 anchor)              (capabilities,                (challenge-
                                      vetted tool hashes)           response auth)

1. A single Ed25519 **root authority** key is generated once and pinned. It is the
   trust anchor: nothing is trusted unless it chains back to this key.
2. At registration the root **signs** a canonical ``AgentManifest`` — agent id, the
   agent's own public key, its capabilities, and the content hashes of the MCP tools
   it is allowed to use. The result is a ``SignedManifest``.
3. At verification time we (a) confirm the manifest's issuer *is* the pinned root
   (chain), (b) verify the Ed25519 signature over the canonical manifest (integrity),
   (c) check it has not expired or been revoked, and optionally (d) confirm the agent
   presents the same public key the root vouched for (binding) and (e) that a tool it
   invokes still matches its pinned hash (anti rug-pull).

Tampering with any manifest field, swapping in an unknown signer, or presenting a key
the root never vouched for all fail closed.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from hashlib import sha256
from typing import Any, Dict, List, Optional, Tuple

from secureagentnet.utils.crypto import (
    generate_ed25519_keypair, sign_message, verify_message,
)
from secureagentnet.utils.persistence import PersistenceStore

logger = logging.getLogger("SecureAgentNet.Identify.TrustChain")

MANIFEST_VERSION = "1"
DEFAULT_VALIDITY_DAYS = 365
_AUTHORITY_KEY = "trust_authority"
_MANIFEST_KEY = "agent_manifests"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _fingerprint(public_key_pem: str) -> str:
    return sha256(public_key_pem.strip().encode("utf-8")).hexdigest()[:16]


class TrustAuthority:
    """The SAN root signing authority — a single, pinned Ed25519 trust anchor.

    The root keypair is generated on first use and persisted. In production the
    private key would live in Vault/an HSM; the env override ``SAN_TRUST_ROOT_KEY``
    (PEM private key) supports that without code changes. The *fingerprint* of the
    root public key is the value everything else is pinned against.
    """

    _cache: Optional["TrustAuthority"] = None

    def __init__(self, private_pem: str, public_pem: str, created_at: str):
        self.private_pem = private_pem
        self.public_pem = public_pem
        self.created_at = created_at
        self.fingerprint = _fingerprint(public_pem)

    @classmethod
    def get(cls) -> "TrustAuthority":
        if cls._cache is not None:
            return cls._cache

        env_priv = os.environ.get("SAN_TRUST_ROOT_KEY")
        if env_priv:
            from cryptography.hazmat.primitives.serialization import (
                load_pem_private_key, Encoding, PublicFormat,
            )
            key = load_pem_private_key(env_priv.encode("utf-8"), password=None)
            public_pem = key.public_key().public_bytes(
                Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
            ).decode("utf-8")
            cls._cache = cls(env_priv, public_pem, _now().isoformat())
            return cls._cache

        record = PersistenceStore.load(_AUTHORITY_KEY, None)
        if not record:
            private_pem, public_pem = generate_ed25519_keypair()
            record = {
                "private_key": private_pem,
                "public_key": public_pem,
                "created_at": _now().isoformat(),
            }
            PersistenceStore.save(_AUTHORITY_KEY, record)
            logger.info("Generated new SAN trust authority root key (fingerprint %s)",
                        _fingerprint(public_pem))

        cls._cache = cls(record["private_key"], record["public_key"], record["created_at"])
        return cls._cache

    @classmethod
    def reset_cache(cls) -> None:
        """Drop the in-process cache (used by tests after rotating the anchor)."""
        cls._cache = None

    def sign(self, message: bytes) -> str:
        return sign_message(self.private_pem, message)


@dataclass
class AgentManifest:
    """The signed-over identity record for a registered agent."""
    agent_id: str
    name: str
    agent_type: str
    public_key: str                       # the agent's OWN public key (may be "")
    capabilities: List[str]
    tool_hashes: Dict[str, str] = field(default_factory=dict)
    issued_at: str = ""
    expires_at: str = ""
    manifest_version: str = MANIFEST_VERSION

    def canonical_bytes(self) -> bytes:
        """Deterministic serialization that the signature is computed over.

        The signature field lives on ``SignedManifest`` and is intentionally never
        part of this payload. Sorting keys makes the bytes reproducible so a re-hash
        on the verifier matches the signer byte-for-byte.
        """
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode("utf-8")

    def fingerprint(self) -> str:
        return sha256(self.canonical_bytes()).hexdigest()[:16]

    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        try:
            return _now() > datetime.fromisoformat(self.expires_at)
        except ValueError:
            return True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AgentManifest":
        return cls(
            agent_id=d["agent_id"],
            name=d.get("name", ""),
            agent_type=d.get("agent_type", "Custom"),
            public_key=d.get("public_key", ""),
            capabilities=list(d.get("capabilities", [])),
            tool_hashes=dict(d.get("tool_hashes", {})),
            issued_at=d.get("issued_at", ""),
            expires_at=d.get("expires_at", ""),
            manifest_version=d.get("manifest_version", MANIFEST_VERSION),
        )


@dataclass
class SignedManifest:
    """An ``AgentManifest`` plus the trust authority's signature over it.

    ``issuer_public_key`` is embedded so a verifier can check the signature *and*
    confirm the issuer chains to the pinned root, in one self-contained object.
    """
    manifest: AgentManifest
    signature: str
    issuer_fingerprint: str
    issuer_public_key: str
    algorithm: str = "ed25519"
    status: str = "active"          # "active" | "revoked"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "manifest": self.manifest.to_dict(),
            "signature": self.signature,
            "issuer_fingerprint": self.issuer_fingerprint,
            "issuer_public_key": self.issuer_public_key,
            "algorithm": self.algorithm,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SignedManifest":
        return cls(
            manifest=AgentManifest.from_dict(d["manifest"]),
            signature=d["signature"],
            issuer_fingerprint=d["issuer_fingerprint"],
            issuer_public_key=d["issuer_public_key"],
            algorithm=d.get("algorithm", "ed25519"),
            status=d.get("status", "active"),
        )


class _ManifestStore:
    """Durable agent_id -> SignedManifest store (separate from the agent DB)."""

    @staticmethod
    def _load() -> Dict[str, Any]:
        return PersistenceStore.load(_MANIFEST_KEY, {}) or {}

    @staticmethod
    def _save(data: Dict[str, Any]) -> None:
        PersistenceStore.save(_MANIFEST_KEY, data)

    @classmethod
    def put(cls, signed: SignedManifest) -> None:
        store = cls._load()
        store[signed.manifest.agent_id] = signed.to_dict()
        cls._save(store)

    @classmethod
    def get(cls, agent_id: str) -> Optional[SignedManifest]:
        rec = cls._load().get(agent_id)
        return SignedManifest.from_dict(rec) if rec else None

    @classmethod
    def set_status(cls, agent_id: str, status: str) -> bool:
        store = cls._load()
        if agent_id not in store:
            return False
        store[agent_id]["status"] = status
        cls._save(store)
        return True

    @classmethod
    def delete(cls, agent_id: str) -> None:
        store = cls._load()
        if store.pop(agent_id, None) is not None:
            cls._save(store)


class TrustChainService:
    """Issue, store, verify and revoke signed agent manifests."""

    # ---- issuance -------------------------------------------------------
    @classmethod
    def issue(
        cls,
        agent: Dict[str, Any],
        tool_hashes: Optional[Dict[str, str]] = None,
        validity_days: int = DEFAULT_VALIDITY_DAYS,
    ) -> SignedManifest:
        """Build, sign and persist a manifest for an agent record."""
        authority = TrustAuthority.get()
        caps = agent.get("capabilities", {})
        if isinstance(caps, dict):
            cap_list = sorted(k for k, v in caps.items() if v)
        else:
            cap_list = sorted(map(str, caps))

        now = _now()
        manifest = AgentManifest(
            agent_id=str(agent["agent_id"]),
            name=agent.get("name", "unknown"),
            agent_type=agent.get("type", "Custom"),
            public_key=agent.get("public_key", "") or "",
            capabilities=cap_list,
            tool_hashes=dict(tool_hashes or {}),
            issued_at=now.isoformat(),
            expires_at=(now + timedelta(days=validity_days)).isoformat(),
        )
        signature = authority.sign(manifest.canonical_bytes())
        signed = SignedManifest(
            manifest=manifest,
            signature=signature,
            issuer_fingerprint=authority.fingerprint,
            issuer_public_key=authority.public_pem,
        )
        _ManifestStore.put(signed)
        logger.info("Issued signed manifest for agent %s (fingerprint %s)",
                    manifest.agent_id, manifest.fingerprint())
        return signed

    @classmethod
    def reissue(cls, agent_id: str, tool_hashes: Optional[Dict[str, str]] = None) -> Optional[SignedManifest]:
        """Re-sign an agent's manifest after its capabilities or key changed."""
        from secureagentnet.identify.identity_registry import IdentityRegistry
        agent = IdentityRegistry.get_agent(agent_id)
        if not agent:
            return None
        if tool_hashes is None:
            existing = _ManifestStore.get(agent_id)
            tool_hashes = existing.manifest.tool_hashes if existing else None
        return cls.issue(agent, tool_hashes=tool_hashes)

    # ---- verification ---------------------------------------------------
    @classmethod
    def verify_signed(cls, signed: SignedManifest) -> Tuple[bool, str]:
        """Verify a SignedManifest: chains to the pinned root, intact, unexpired.

        This is the heart of the trust chain. Order matters — we reject an untrusted
        signer *before* trusting its embedded key to check a signature.
        """
        authority = TrustAuthority.get()

        # 1) Chain: the issuer must be the pinned trust anchor.
        if _fingerprint(signed.issuer_public_key) != authority.fingerprint:
            return False, "issuer is not the pinned SAN trust authority (broken chain)"
        if signed.issuer_fingerprint != authority.fingerprint:
            return False, "issuer fingerprint does not match the trust anchor"

        # 2) Revocation.
        if signed.status != "active":
            return False, f"manifest status is '{signed.status}'"

        # 3) Integrity: Ed25519 signature over the canonical manifest.
        if not verify_message(signed.issuer_public_key,
                              signed.manifest.canonical_bytes(),
                              signed.signature):
            return False, "manifest signature is invalid (tampered or wrong key)"

        # 4) Validity window.
        if signed.manifest.is_expired():
            return False, "manifest has expired"

        return True, "trust chain verified"

    @classmethod
    def verify_agent(
        cls,
        agent_id: str,
        presented_public_key: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Verify a registered agent's stored manifest (fail-closed).

        If ``presented_public_key`` is given, also bind it: the key the agent
        authenticates with must be the one the root vouched for.
        """
        signed = _ManifestStore.get(agent_id)
        if signed is None:
            return False, "agent has no signed manifest (fail-closed)"
        if signed.manifest.agent_id != agent_id:
            return False, "manifest agent_id mismatch"

        ok, reason = cls.verify_signed(signed)
        if not ok:
            return False, reason

        if presented_public_key is not None:
            if (signed.manifest.public_key or "").strip() != (presented_public_key or "").strip():
                return False, "presented public key is not the key vouched for by the manifest"

        return True, "trust chain verified"

    @classmethod
    def verify_tool(cls, agent_id: str, tool_name: str, content_hash: str) -> Tuple[bool, str]:
        """Confirm an invoked tool still matches the hash pinned in the manifest.

        Catches a rug-pull at the trust-chain level: a tool whose definition changed
        since the manifest was signed no longer matches and is rejected.
        """
        signed = _ManifestStore.get(agent_id)
        if signed is None:
            return False, "agent has no signed manifest (fail-closed)"
        pinned = signed.manifest.tool_hashes.get(tool_name)
        if pinned is None:
            return False, f"tool '{tool_name}' is not pinned in the agent's manifest"
        if pinned != content_hash:
            return False, f"tool '{tool_name}' hash differs from the manifest (rug-pull)"
        return True, "tool matches pinned manifest hash"

    # ---- lifecycle ------------------------------------------------------
    @classmethod
    def get_manifest(cls, agent_id: str) -> Optional[SignedManifest]:
        return _ManifestStore.get(agent_id)

    @classmethod
    def revoke(cls, agent_id: str) -> bool:
        return _ManifestStore.set_status(agent_id, "revoked")

    @classmethod
    def delete(cls, agent_id: str) -> None:
        _ManifestStore.delete(agent_id)

    @classmethod
    def root_fingerprint(cls) -> str:
        return TrustAuthority.get().fingerprint
