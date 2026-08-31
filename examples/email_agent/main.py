import os
from pathlib import Path
from dotenv import load_dotenv

from email_client import GmailClient
from ai_agent import EmailAgent

# Explicit path: under `san agent run` the working directory is the sandbox
# workspace, not this folder, so a bare load_dotenv() would find nothing.
load_dotenv(Path(__file__).parent / ".env")

# /agent-src is mounted read-only inside the sandbox; /workspace is the tmpfs
# the runtime hands back as output_files. Outside the sandbox, write locally.
DRAFTS_DIR = Path(
    os.environ.get("EMAIL_AGENT_DRAFTS_DIR")
    or ("/workspace/drafts" if os.environ.get("SAN_SUPERVISED") == "1"
        else Path(__file__).parent / "drafts")
)


def main():
    gmail_address = os.environ["GMAIL_ADDRESS"]
    gmail_app_password = os.environ["GMAIL_APP_PASSWORD"]
    openai_api_key = os.environ["OPENAI_API_KEY"]
    openai_model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    trusted_senders = {
        s.strip().lower()
        for s in os.environ.get("TRUSTED_SENDERS", "").split(",")
        if s.strip()
    }

    mail = GmailClient(gmail_address, gmail_app_password)
    user_name = os.environ.get("USER_NAME", "the user")
    agent = EmailAgent(openai_api_key, model=openai_model, user_name=user_name)
    print("Fetching unread emails...")
    unread = mail.fetch_unread(limit=10)
    print(f"Found {len(unread)} unread email(s).\n")

    if not unread:
        return

    DRAFTS_DIR.mkdir(parents=True, exist_ok=True)
    for msg in unread:
        sender_email = mail.sender_email_only(msg["sender"])
        print(f"Analyzing: '{msg['subject']}' from {sender_email}")

        result = agent.analyze(
            sender=msg["sender"],
            subject=msg["subject"],
            body=msg["body"],
        )

        print(f"  -> category: {result['category']}")
        print(f"  -> summary:  {result['summary']}")

        mail.add_label(msg["id"], result["category"])

        if result.get("needs_reply") and result.get("draft_reply"):
            if sender_email.lower() in trusted_senders:
                mail.send_reply(
                    to_address=sender_email,
                    subject=msg["subject"],
                    body=result["draft_reply"],
                    in_reply_to=msg["message_id_header"],
                )
                print(f"  -> reply sent directly to {sender_email} (trusted sender)")
            else:
                draft_path = DRAFTS_DIR / f"{msg['id']}.txt"
                draft_path.write_text(
                    f"To: {sender_email}\n"
                    f"Subject: Re: {msg['subject']}\n\n"
                    f"{result['draft_reply']}\n"
                )
                print(f"  -> draft reply saved to {draft_path}")
                if os.environ.get("SAN_SUPERVISED") == "1":
                    # The sandbox workspace is discarded with the container and
                    # is not readable from the host, so stdout is the only way
                    # the draft survives a supervised run.
                    print(f"--- draft {msg['id']} ---")
                    print(draft_path.read_text())
                    print(f"--- end draft {msg['id']} ---")

        print()

    if os.environ.get("SAN_SUPERVISED") == "1":
        # The sandbox workspace is not reachable from the host, so point the
        # operator at the stdout copy rather than a path they cannot open.
        print("Done. Drafts are printed above; review them before sending anything.")
    else:
        print(f"Done. Review drafts in {DRAFTS_DIR} before sending anything.")


if __name__ == "__main__":
    main()


    