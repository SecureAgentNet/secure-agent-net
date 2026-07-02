"""SecureAgentNet Cloud Console — the central, multi-endpoint security console.

A separate, hosted service that many local SecureAgentNet daemons report up to.
It aggregates *metadata only* (decisions, alerts, agent inventory, trust scores,
heartbeats) — never raw payloads or PII — and lets an admin observe the whole
fleet and remotely trip an endpoint's kill-switch.

This package is an independent deployable: it has its own database, settings and
FastAPI app, and shares only small utilities with the per-host gateway.
"""

__version__ = "0.1.0"
