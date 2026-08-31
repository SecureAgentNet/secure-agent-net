# Email AI Agent

Reads unread Gmail messages, uses OpenAI to summarize and categorize each
one, applies a Gmail label, and either auto-sends a reply (for trusted
senders) or saves a draft reply locally for review.

## Setup

1. **Copy the environment template:**
```bash
   cp .env.example .env
```

2. **Fill in `.env`:**
   - `GMAIL_ADDRESS` / `GMAIL_APP_PASSWORD` — a Gmail App Password, not your
     normal password. Generate one at
     https://myaccount.google.com/apppasswords (requires 2-Step Verification).
   - `OPENAI_API_KEY` — from https://platform.openai.com/api-keys
   - `TRUSTED_SENDERS` — comma-separated emails that get auto-replies.
     Everyone else gets a draft saved to `drafts/` instead.
   - `USER_NAME` — used to sign replies.

3. **Install dependencies** (run from inside this folder, with your venv active):
```bash
   pip install -r requirements.txt
```

4. **Run it:**
```bash
   python main.py
```

## How it's structured

- `email_client.py` — all Gmail I/O (IMAP to read, SMTP to send). Knows
  nothing about AI.
- `ai_agent.py` — talks to OpenAI, returns structured JSON
  (`category`, `summary`, `needs_reply`, `draft_reply`). Knows nothing
  about Gmail.
- `main.py` — the only file that combines both: fetch → analyze → label →
  auto-send or draft.

## Notes

- Only genuinely **unread** emails are processed, sorted newest-first by
  their actual send date.
- Gmail labels are applied with an `AI-` prefix (e.g. `AI-urgent`) to avoid
  colliding with Gmail's reserved system labels like `Spam`.
- Auto-send only fires for addresses in `TRUSTED_SENDERS`; everyone else
  gets a reviewable draft in `drafts/` (which is gitignored — those are
  personal/work correspondence, not source code).
- Requires a normal, unrestricted network connection — some public WiFi
  networks block or interfere with IMAP (port 993).