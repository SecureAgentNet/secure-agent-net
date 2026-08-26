"""Run the multi-account FinanceOps simulator through SecureAgentNet."""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from examples.finance_agent.runtime import connect, generate_keypair, register_and_commission, start_gateway

from .agent import FinancePaymentAgent
from .contract import contract_for_framework
from .payment_engine import FinanceOpsStore


def main() -> None:
    parser = argparse.ArgumentParser(description="SecureAgentNet FinanceOps payment simulation")
    parser.add_argument("--provider", default="classifier", help="DECIDE provider (default: classifier)")
    parser.add_argument("--root", default=os.environ.get("SAN_FINANCE_OPS_DIR", "/tmp/san-finance-ops"))
    parser.add_argument(
        "--san-data-dir",
        help="Share SAN identity/audit storage with another process (use ~/.secureagentnet for Desktop observation)",
    )
    parser.add_argument("--gateway-url", help="Use an already running SAN gateway")
    parser.add_argument("--langchain", action="store_true", help="Use the LangChain payment coordinator")
    parser.add_argument("--interactive", action="store_true", help="Open a terminal prompt loop (requires --langchain)")
    parser.add_argument("--model", help="Ollama model for --langchain (default: llama3.2)")
    args = parser.parse_args()
    if args.interactive and not args.langchain:
        parser.error("--interactive requires --langchain")

    root = Path(args.root)
    # Store identity, mandate and database state beside this simulation rather
    # than in the user's global SAN directory.
    san_root = Path(args.san_data_dir).expanduser() if args.san_data_dir else root
    os.environ["INSTALL_DIR"] = str(san_root)
    os.environ["DATABASE_URL"] = f"sqlite:///{san_root / 'data' / 'securenet.db'}"
    source = Path(__file__).with_name("finance_ops_seed.csv")
    store = FinanceOpsStore(source, root)
    store.load()
    private_key, public_key = generate_keypair()
    agent_id = register_and_commission(public_key)

    gateway = None
    try:
        if args.gateway_url:
            base_url = args.gateway_url
        else:
            gateway = start_gateway(provider=args.provider, log_path=str(root / "gateway.log"))
            base_url = gateway.base_url
        executor = connect(base_url, agent_id, private_key)
        executor._client.login()
        contract = contract_for_framework("langchain" if args.langchain else "custom-python")
        agent = FinancePaymentAgent(store, executor, agent_id, contract=contract)

        print("FinanceOps: SecureAgentNet-governed simulated payment rail")
        if args.langchain:
            from .langchain_agent import build_langchain_agent, interactive_session, run_task

            coordinator = build_langchain_agent(store, agent, executor, args.model)
            if args.interactive:
                interactive_session(coordinator)
                print(f"Released simulated transactions: {len(store.released_payments())}")
                print(f"Inspect: {root / 'released_payments.json'}")
                return
            result = run_task(
                coordinator,
                "Review PAY-001, then process it if it is appropriate. Report the workflow result.",
            )
            print("LangChain coordinator completed its bounded tool loop.")
            for message in result.get("messages", []):
                if message.__class__.__name__ == "ToolMessage":
                    print(f"  tool → {str(message.content)[:180]}")
            print(f"Released simulated transactions: {len(store.released_payments())}")
            return
        for request_id in ("PAY-001", "PAY-002", "PAY-003", "PAY-004", "ATT-001", "ATT-002", "ATT-003"):
            result = agent.process(request_id)
            print(f"{request_id}: {result['state']} — {result['reason']}")
        approval = agent.approve("PAY-003", "finance-manager-001")
        print(f"PAY-003 approval: {approval['state']} — {approval['reason']}")
        print(f"Released simulated transactions: {len(store.released_payments())}")
        print(f"Inspect: {root / 'released_payments.json'}")
    finally:
        if gateway is not None:
            gateway.stop()


if __name__ == "__main__":
    main()
