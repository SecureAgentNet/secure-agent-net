import imaplib
import smtplib
import email
from email.header import decode_header
from email.mime.text import MIMEText
from email.utils import parseaddr
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime


class GmailClient:
    def __init__(self, address: str, app_password: str):
        self.address = address
        self.app_password = app_password

    def fetch_unread(self, limit: int = 10) -> list[dict]:
        results = []

        imap = imaplib.IMAP4_SSL("imap.gmail.com", 993)
        imap.login(self.address, self.app_password)
        imap.select("INBOX")

        status, message_numbers = imap.search(None, "UNSEEN")
        if status != "OK":
            imap.logout()
            return results

        ids = message_numbers[0].split()

        for msg_id in ids:
            status, msg_data = imap.fetch(msg_id, "(RFC822)")
            if status != "OK":
                continue

            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)

            results.append({
                "id": msg_id.decode(),
                "sender": self._decode(msg.get("From", "")),
                "subject": self._decode(msg.get("Subject", "")),
                "message_id_header": msg.get("Message-ID", ""),
                "date": msg.get("Date", ""),
                "body": self._extract_body(msg),
            })

        imap.logout()

        results.sort(key=lambda m: self._parse_date(m["date"]), reverse=True)
        return results[:limit]

    def add_label(self, msg_id: str, label: str) -> None:
        imap = imaplib.IMAP4_SSL("imap.gmail.com", 993)
        imap.login(self.address, self.app_password)
        imap.select("INBOX")
        imap.store(msg_id, "+X-GM-LABELS", f'("{label}")')
        imap.logout()

    def send_reply(self, to_address: str, subject: str, body: str,
                    in_reply_to: str = "") -> None:
        msg = MIMEText(body)
        msg["From"] = self.address
        msg["To"] = to_address
        msg["Subject"] = subject if subject.startswith("Re:") else f"Re: {subject}"

        if in_reply_to:
            msg["In-Reply-To"] = in_reply_to
            msg["References"] = in_reply_to

        with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
            smtp.starttls()
            smtp.login(self.address, self.app_password)
            smtp.send_message(msg)

    @staticmethod
    def _decode(header_value: str) -> str:
        if not header_value:
            return ""
        decoded_parts = decode_header(header_value)
        return "".join(
            part.decode(enc or "utf-8") if isinstance(part, bytes) else part
            for part, enc in decoded_parts
        )

    @staticmethod
    def _parse_date(date_header: str):
        try:
            dt = parsedate_to_datetime(date_header)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (TypeError, ValueError):
            return datetime.min.replace(tzinfo=timezone.utc)

    @staticmethod
    def _extract_body(msg) -> str:
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                disposition = str(part.get("Content-Disposition", ""))
                if content_type == "text/plain" and "attachment" not in disposition:
                    charset = part.get_content_charset() or "utf-8"
                    return part.get_payload(decode=True).decode(charset, errors="replace")
            return ""
        else:
            charset = msg.get_content_charset() or "utf-8"
            return msg.get_payload(decode=True).decode(charset, errors="replace")

    @staticmethod
    def sender_email_only(sender_header: str) -> str:
        return parseaddr(sender_header)[1]