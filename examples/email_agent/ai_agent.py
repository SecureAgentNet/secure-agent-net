import json
from openai import OpenAI

CATEGORIES = ["urgent", "action_needed", "fyi", "newsletter", "spam"]

SYSTEM_PROMPT = f"""You are an email triage assistant. For each email you are shown,
analyze it and respond with ONLY a JSON object (no markdown, no extra text) with
exactly these fields:

- "category": one of {CATEGORIES}
- "summary": a 1-2 sentence plain-English summary of the email
- "needs_reply": true or false
- "draft_reply": if needs_reply is true, a short, polite, professional draft
  reply written on behalf of the user. If false, an empty string.

Be conservative: only mark "urgent" for genuinely time-sensitive matters,
and only draft a reply when the email actually expects a response from the user
(not for newsletters, receipts, or automated notifications).
"""


class EmailAgent:
    def __init__(self, api_key: str, model: str = "gpt-4o-mini", user_name: str = "the user"):
        self.client = OpenAI(api_key=api_key)
        self.model = model
        self.user_name = user_name

    def analyze(self, sender: str, subject: str, body: str) -> dict:
        trimmed_body = body[:4000]

        user_content = (
            f"From: {sender}\n"
            f"Subject: {subject}\n\n"
            f"{trimmed_body}"
        )

        system_prompt = SYSTEM_PROMPT + (
            f"\n\nEnd the draft_reply with a sign-off on its own line, "
            f"formatted exactly like this at the very end:\n"
            f"Best regards,\n{self.user_name}"
        )

        response = self.client.chat.completions.create(
            model=self.model,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
            temperature=0.3,
        )

        raw = response.choices[0].message.content
        return self._safe_parse(raw)

    @staticmethod
    def _safe_parse(raw: str) -> dict:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return {
                "category": "fyi",
                "summary": "(Could not parse AI response)",
                "needs_reply": False,
                "draft_reply": "",
            }

        if data.get("category") not in CATEGORIES:
            data["category"] = "fyi"

        return data