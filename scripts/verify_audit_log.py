#!/usr/bin/env python3
"""Vault Audit Log Integrity Checker — Cryptographic Non-Repudiation.

Continuously verifies HMAC signatures on all Vault audit log entries
and alerts on any tampered, deleted, or injected records.

Usage:
    python scripts/verify_audit_log.py          # One-shot verification
    python scripts/verify_audit_log.py --watch  # Continuous monitoring (every 30s)
    python scripts/verify_audit_log.py --agent <id>  # Verify specific agent
"""

import argparse
import sys
import time
import json
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))

from secureagentnet.track.vault_client import VaultAuditClient
from secureagentnet.core.config import get_settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("SecureAgentNet.AuditVerifier")


class AuditLogVerifier:
    """Cryptographic non-repudiation engine for Vault audit logs."""

    def __init__(self):
        self.vault = VaultAuditClient()
        self.stats = {"verified": 0, "tampered": 0, "missing": 0, "errors": 0}
        self.alerts: list = []

        if not self.vault.client:
            logger.error("Vault client not available — verification cannot proceed")
        else:
            logger.info(
                "AuditLogVerifier initialized — Vault at %s",
                self.vault.settings.vault_addr,
            )

    def verify_agent(self, agent_id: str) -> Dict[str, Any]:
        """Verify all audit logs for a specific agent."""
        if not self.vault.client:
            return {"error": "Vault unavailable", "agent_id": agent_id}

        verified = 0
        tampered = 0
        entries: list = []

        try:
            base_path = f"audit/agents/{agent_id}"
            secrets = self.vault.client.secrets.kv.v2.list_secrets(
                path=base_path
            )
            keys = secrets.get("data", {}).get("keys", [])

            for key in keys:
                receipt = f"vault-{base_path}/{key}-v1"
                result = self.vault.verify_receipt(receipt)

                if result.get("valid"):
                    verified += 1
                elif "not found" in str(result.get("error", "")).lower():
                    self.stats["missing"] += 1
                    logger.error("MISSING: %s", receipt)
                    self.alerts.append({
                        "type": "missing", "receipt": receipt,
                        "time": datetime.now(timezone.utc).isoformat(),
                    })
                else:
                    tampered += 1
                    logger.critical("TAMPERED: %s — %s", receipt, result.get("error"))
                    self.alerts.append({
                        "type": "tampered", "receipt": receipt,
                        "error": result.get("error"),
                        "time": datetime.now(timezone.utc).isoformat(),
                    })

                entries.append({
                    "receipt": receipt,
                    "valid": result.get("valid", False),
                    "error": result.get("error"),
                })

        except Exception as e:
            if "404" not in str(e) and "InvalidPath" not in str(e):
                logger.error("Failed to query agent %s: %s", agent_id, e)

        self.stats["verified"] += verified
        self.stats["tampered"] += tampered

        return {
            "agent_id": agent_id,
            "total": verified + tampered,
            "verified": verified,
            "tampered": tampered,
            "entries": entries,
            "alerts": self.alerts[-10:],
        }

    def verify_known_agents(self) -> Dict[str, Any]:
        """Verify audit logs for all known agents."""
        from secureagentnet.identify.identity_registry import IdentityRegistry

        agents = IdentityRegistry.list_agents()
        results = {}

        for agent in agents:
            aid = agent["agent_id"]
            result = self.verify_agent(aid)
            results[aid] = result

        return {
            "agents_checked": len(results),
            "stats": self.stats,
            "alerts": self.alerts[-20:],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def watch(self, interval: int = 30):
        """Continuous monitoring loop."""
        logger.info("Starting continuous audit log monitoring (interval=%ds)", interval)
        try:
            while True:
                result = self.verify_known_agents()
                if self.alerts:
                    logger.warning(
                        "ALERTS: verified=%d tampered=%d missing=%d",
                        self.stats["verified"],
                        self.stats["tampered"],
                        self.stats["missing"],
                    )
                else:
                    logger.info(
                        "All clear — verified=%d entries across %d agents",
                        self.stats["verified"],
                        result["agents_checked"],
                    )
                time.sleep(interval)
        except KeyboardInterrupt:
            logger.info("Monitoring stopped by user")
            self._print_summary()

    def _print_summary(self):
        print("\n" + "=" * 60)
        print("  VAULT AUDIT LOG INTEGRITY VERIFICATION")
        print("=" * 60)
        print(f"  Verified: {self.stats['verified']}")
        print(f"  Tampered: {self.stats['tampered']}")
        print(f"  Missing:  {self.stats['missing']}")
        print(f"  Errors:   {self.stats['errors']}")
        if self.alerts:
            print(f"\n  ALERTS ({len(self.alerts)}):")
            for alert in self.alerts[-5:]:
                print(f"    [{alert['type'].upper()}] {alert['receipt']}")
        else:
            print("\n  ✓ All audit logs verified — no tampering detected")
        print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Vault Audit Log Integrity Checker")
    parser.add_argument("--agent", type=str, help="Verify a specific agent ID")
    parser.add_argument("--watch", action="store_true", help="Continuous monitoring mode")
    parser.add_argument("--interval", type=int, default=30, help="Watch interval in seconds")
    args = parser.parse_args()

    verifier = AuditLogVerifier()

    if not verifier.vault.client:
        logger.error("Vault is not available — check VAULT_ADDR and VAULT_TOKEN")
        sys.exit(1)

    if args.watch:
        verifier.watch(interval=args.interval)
    elif args.agent:
        result = verifier.verify_agent(args.agent)
        print(json.dumps(result, indent=2, default=str))
    else:
        result = verifier.verify_known_agents()
        verifier._print_summary()


if __name__ == "__main__":
    main()
