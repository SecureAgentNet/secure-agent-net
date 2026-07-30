"""Run the LangChain email agent through the SecureAgentNet MCP gateway:

    python -m examples.langchain_email_agent                 # boots the gateway, poisoned inbox
    python -m examples.langchain_email_agent --benign        # benign inbox only
    python -m examples.langchain_email_agent --provider classifier   # fast, offline DECIDE
    python -m examples.langchain_email_agent --gateway-url http://127.0.0.1:5000  # reuse a running gateway
"""
from __future__ import annotations

import argparse

from .agent import DEFAULT_MODEL, run


def main() -> None:
    parser = argparse.ArgumentParser(
        description="LangChain email agent governed by the SecureAgentNet MCP gateway")
    parser.add_argument("--benign", action="store_true",
                        help="Seed a benign inbox (no prompt-injection email)")
    parser.add_argument("--model", default=DEFAULT_MODEL,
                        help=f"Ollama model to drive the agent (default {DEFAULT_MODEL})")
    parser.add_argument("--provider", default=None,
                        help="DECIDE model provider for the gateway (ollama|classifier|hosted_api)")
    parser.add_argument("--gateway-url", default=None,
                        help="Use an already-running gateway instead of booting one")
    args = parser.parse_args()
    run(poisoned=not args.benign, model_name=args.model,
        provider=args.provider, gateway_url=args.gateway_url)


if __name__ == "__main__":
    main()
