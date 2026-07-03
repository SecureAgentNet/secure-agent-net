"""Trust chain / manifest signing tests (Deliverable 3: Cryptographic Toolkit)."""
import pytest

from secureagentnet.utils.crypto import (
    generate_ed25519_keypair, sign_message, verify_message, verify_signature,
)
from secureagentnet.identify.trust_chain import (
    TrustAuthority, TrustChainService, AgentManifest, SignedManifest,
)
from secureagentnet.identify.identity_registry import IdentityRegistry


# --- crypto layer -------------------------------------------------------
class TestEd25519Crypto:
    def test_keypair_sign_verify_roundtrip(self):
        priv, pub = generate_ed25519_keypair()
        sig = sign_message(priv, b"hello world")
        assert verify_message(pub, b"hello world", sig) is True

    def test_verify_fails_on_tampered_message(self):
        priv, pub = generate_ed25519_keypair()
        sig = sign_message(priv, b"original")
        assert verify_message(pub, b"tampered", sig) is False

    def test_verify_fails_with_wrong_key(self):
        priv, _ = generate_ed25519_keypair()
        _, other_pub = generate_ed25519_keypair()
        sig = sign_message(priv, b"data")
        assert verify_message(other_pub, b"data", sig) is False

    def test_challenge_response_now_supports_ed25519(self):
        # verify_signature previously only handled RSA/EC; Ed25519 must work too.
        priv, pub = generate_ed25519_keypair()
        nonce = "deadbeefcafe"
        sig = sign_message(priv, nonce.encode())
        assert verify_signature(pub, nonce, sig) is True


# --- trust chain --------------------------------------------------------
class TestTrustChain:
    def _agent(self, **over):
        a = {
            "agent_id": "agent-xyz",
            "name": "trusted-bot",
            "type": "LangChain",
            "public_key": "agent-own-key",
            "capabilities": {"execute": True, "read_file": True, "denied": False},
        }
        a.update(over)
        return a

    def test_issue_then_verify(self):
        signed = TrustChainService.issue(self._agent())
        assert isinstance(signed, SignedManifest)
        ok, reason = TrustChainService.verify_signed(signed)
        assert ok is True, reason
        # capabilities are bound (only truthy ones, sorted)
        assert signed.manifest.capabilities == ["execute", "read_file"]
        assert signed.issuer_fingerprint == TrustChainService.root_fingerprint()

    def test_tampered_manifest_field_fails(self):
        signed = TrustChainService.issue(self._agent())
        signed.manifest.capabilities.append("delete_database")  # privilege escalation
        ok, reason = TrustChainService.verify_signed(signed)
        assert ok is False
        assert "signature is invalid" in reason

    def test_tampered_signature_fails(self):
        signed = TrustChainService.issue(self._agent())
        signed.signature = ("0" * len(signed.signature))
        ok, reason = TrustChainService.verify_signed(signed)
        assert ok is False

    def test_untrusted_issuer_breaks_chain(self):
        # Forge a manifest signed by a stray key impersonating the authority.
        rogue_priv, rogue_pub = generate_ed25519_keypair()
        manifest = AgentManifest(
            agent_id="agent-xyz", name="evil", agent_type="Custom",
            public_key="k", capabilities=["execute"],
            issued_at="2026-01-01T00:00:00+00:00",
            expires_at="2999-01-01T00:00:00+00:00",
        )
        forged = SignedManifest(
            manifest=manifest,
            signature=sign_message(rogue_priv, manifest.canonical_bytes()),
            issuer_fingerprint="deadbeef",
            issuer_public_key=rogue_pub,
        )
        ok, reason = TrustChainService.verify_signed(forged)
        assert ok is False
        assert "pinned SAN trust authority" in reason

    def test_expired_manifest_fails(self):
        signed = TrustChainService.issue(self._agent(), validity_days=-1)
        ok, reason = TrustChainService.verify_signed(signed)
        assert ok is False
        assert "expired" in reason

    def test_empty_expiry_is_treated_as_expired(self):
        # Fail-closed: a manifest with a missing/blank expires_at (legacy or tampered
        # record) must NOT be treated as never-expiring.
        manifest = AgentManifest(
            agent_id="a", name="n", agent_type="Custom", public_key="k",
            capabilities=["execute"], issued_at="2026-01-01T00:00:00+00:00",
            expires_at="",
        )
        assert manifest.is_expired() is True

    def test_revoked_manifest_fails(self):
        TrustChainService.issue(self._agent(agent_id="rev-1"))
        assert TrustChainService.revoke("rev-1") is True
        ok, reason = TrustChainService.verify_agent("rev-1")
        assert ok is False
        assert "revoked" in reason

    def test_verify_agent_key_binding(self):
        TrustChainService.issue(self._agent(agent_id="bind-1", public_key="real-key"))
        ok, _ = TrustChainService.verify_agent("bind-1", presented_public_key="real-key")
        assert ok is True
        bad, reason = TrustChainService.verify_agent("bind-1", presented_public_key="attacker-key")
        assert bad is False
        assert "vouched for" in reason

    def test_verify_agent_without_manifest_fails_closed(self):
        ok, reason = TrustChainService.verify_agent("never-registered")
        assert ok is False
        assert "fail-closed" in reason

    def test_tool_hash_pinning_and_rugpull(self):
        TrustChainService.issue(
            self._agent(agent_id="tool-1"),
            tool_hashes={"weather": "hash-abc"},
        )
        ok, _ = TrustChainService.verify_tool("tool-1", "weather", "hash-abc")
        assert ok is True
        rug, reason = TrustChainService.verify_tool("tool-1", "weather", "hash-CHANGED")
        assert rug is False
        assert "rug-pull" in reason
        unp, reason2 = TrustChainService.verify_tool("tool-1", "unknown", "x")
        assert unp is False
        assert "not pinned" in reason2


# --- integration with the registry -------------------------------------
class TestRegistryTrustIntegration:
    def test_registration_auto_issues_verifiable_manifest(self):
        agent = IdentityRegistry.register_agent({
            "name": "auto-bot", "type": "CrewAI",
            "public_key": "auto-key", "capabilities": {"execute": True},
        })
        signed = TrustChainService.get_manifest(agent["agent_id"])
        assert signed is not None
        ok, reason = TrustChainService.verify_agent(agent["agent_id"])
        assert ok is True, reason
        assert agent["metadata"]["manifest_issuer"] == TrustChainService.root_fingerprint()

    def test_capability_change_reissues_manifest(self):
        agent = IdentityRegistry.register_agent({
            "name": "grow-bot", "public_key": "k1",
            "capabilities": {"read_file": True},
        })
        before = TrustChainService.get_manifest(agent["agent_id"]).manifest.fingerprint()
        IdentityRegistry.update_agent(agent["agent_id"],
                                      {"capabilities": {"read_file": True, "execute": True}})
        after_signed = TrustChainService.get_manifest(agent["agent_id"])
        assert after_signed.manifest.fingerprint() != before
        assert "execute" in after_signed.manifest.capabilities
        ok, reason = TrustChainService.verify_signed(after_signed)
        assert ok is True, reason

    def test_deregister_removes_manifest(self):
        agent = IdentityRegistry.register_agent({
            "name": "temp-bot", "public_key": "k", "capabilities": {},
            "created_by": "auto-discover",
        })
        aid = agent["agent_id"]
        assert TrustChainService.get_manifest(aid) is not None
        IdentityRegistry.deregister_agent(aid)
        assert TrustChainService.get_manifest(aid) is None
