"""A real LangChain email agent, guarded end-to-end by SecureAgentNet.

This package is a *runnable test harness* for the SAN pipeline: a genuine
LangChain tool-calling agent (ChatOllama brain) that reads a support inbox and
sends replies — with every tool call routed through Identify→Track→Contain→Decide.

- ``mailbox``  — a real local maildir (inbox/outbox) seeded with genuine support
  emails and one *poisoned* email carrying an indirect prompt-injection payload.
- ``tools``    — the agent's LangChain tools, SAN-secured (read/list/reply are
  adjudicated in-process; a shell tool is fully sandboxed).
- ``agent``    — commissions the agent with a mandate and builds the LangChain
  agent; ``python -m examples.langchain_email_agent`` runs it against Ollama.
"""
