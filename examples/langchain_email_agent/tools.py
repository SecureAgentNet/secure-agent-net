"""The email agent's tools — real LangChain tools whose every call is adjudicated
by the **MCP gateway** over HTTP.

Each tool is wrapped with ``secure_tool(..., enforce_only=True, executor=Remote…)``:
the call is sent to ``POST /api/v1/mcp/execute`` (authenticated), the gateway runs
the full ITCD pipeline and returns a verdict, and on approval the tool's real body
(reading the maildir / writing the outbox) runs. A reply redirected to an external
address, or a shell command reading a private key, is blocked *at the gateway*.
"""
from __future__ import annotations

from typing import List

from langchain_core.tools import tool

from secureagentnet.integrations.base import SecureExecutor
from secureagentnet.integrations.langchain import secure_tool

from .mailbox import Mailbox


def build_gateway_tools(mailbox: Mailbox, executor: SecureExecutor) -> List:
    """Build the agent's LangChain tools, each governed by the MCP gateway.

    ``executor`` is a ``RemoteExecutor`` bound to the running gateway (see
    ``runtime.connect``).
    """

    @tool
    def list_inbox() -> str:
        """List the emails waiting in the support inbox (id, sender, subject)."""
        rows = mailbox.list_inbox()
        if not rows:
            return "(inbox is empty)"
        return "\n".join(f"[{r['id']}] from {r['from']} — {r['subject']}" for r in rows)

    @tool
    def read_email(email_id: str) -> str:
        """Read the full text of one inbox email by its id (e.g. '01_refund')."""
        m = mailbox.read(email_id)
        if not m:
            return f"No email with id {email_id!r}."
        return f"From: {m['from']}\nSubject: {m['subject']}\n\n{m['body']}"

    @tool
    def send_reply(to: str, subject: str, body: str) -> str:
        """Send an email reply. `to` = recipient address, `subject`/`body` = the message."""
        return mailbox.send(to, subject, body)

    # Each tool is adjudicated by the gateway; the real body runs only on approval.
    secure_list = secure_tool(
        list_inbox, action_name="read_file", target_resource="support-inbox",
        intent_summary="List the support inbox", enforce_only=True, executor=executor)
    secure_read = secure_tool(
        read_email, action_name="read_file", target_resource="support-inbox",
        intent_summary="Read a support email", enforce_only=True, executor=executor)
    # For a reply the DECIDE target is the recipient, so redirecting a reply to an
    # external/attacker address is judged against the mandate on this very call.
    secure_send = secure_tool(
        send_reply, action_name="send_email",
        intent_summary="Send a support reply to a customer", enforce_only=True,
        target_resolver=lambda args, kwargs: kwargs.get("to") or (args[0] if args else "recipient"),
        executor=executor)

    return [secure_list, secure_read, secure_send]
