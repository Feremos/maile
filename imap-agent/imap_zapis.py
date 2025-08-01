import sys
import os   
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import imaplib
import email
from email.header import decode_header
from datetime import datetime, timedelta
from app.db import get_session
from app.models import GmailCredentials, Email
from cryptography.fernet import Fernet
from email.utils import parsedate_to_datetime
from dotenv import load_dotenv
import re

load_dotenv()

fernet = Fernet(os.getenv("FERNET_KEY"))

def decode_mime_words(s):
    decoded = decode_header(s)
    result = []
    for text, encoding in decoded:
        if isinstance(text, bytes):
            try:
                encoding = (encoding or 'utf-8').lower()
                if encoding == 'unknown-8bit':
                    encoding = 'utf-8'
                result.append(text.decode(encoding, errors='replace'))
            except Exception:
                result.append(text.decode('utf-8', errors='replace'))
        else:
            result.append(text)
    return ''.join(result)

def is_html(text):
    # Sprawdza, czy tekst zawiera podstawowe tagi HTML
    return bool(re.search(r'<(html|body|div|span|!DOCTYPE)', text, re.IGNORECASE))

def fetch_emails_from_imap(creds: GmailCredentials):
    try:
        mail = imaplib.IMAP4_SSL(creds.imap_server, creds.imap_port)
        decrypted_password = fernet.decrypt(creds.encrypted_password.encode()).decode()
        mail.login(creds.login, decrypted_password)
        mail.select("inbox")

        status, messages = mail.search(None, "UNSEEN")
        email_ids = messages[0].split()

        fetched = []

        now = datetime.now()
        yesterday_17 = (now - timedelta(days=1)).replace(hour=17, minute=0, second=0, microsecond=0)

        email_ids = messages[0].split()
        email_ids = email_ids[::-1]
        for eid in email_ids:
            _, msg_data = mail.fetch(eid, "(BODY.PEEK[])")
            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)

            subject = decode_mime_words(msg.get("Subject", ""))
            from_ = msg.get("From", "")
            to_ = msg.get("To", "")
            date_raw = msg.get("Date")
            message_id = msg.get("Message-ID")

            body = ""
            skip = False

            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain" and not part.get("Content-Disposition"):
                        payload = part.get_payload(decode=True)
                        try:
                            text = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
                        except:
                            text = payload.decode("utf-8", errors="replace")

                        if is_html(text):
                            skip = True
                            break
                        else:
                            body = text
                            break
            else:
                payload = msg.get_payload(decode=True)
                try:
                    text = payload.decode(msg.get_content_charset() or "utf-8", errors="replace")
                except:
                    text = payload.decode("utf-8", errors="replace")

                if is_html(text):
                    skip = True
                else:
                    body = text

            if skip:
                print(f"⛔ Pominięto maila z HTML: {subject}")
                continue

            try:
                received_at = parsedate_to_datetime(date_raw)
                received_at_naive = received_at.replace(tzinfo=None)
                print(f"Data maila: {received_at_naive}, filtrowana względem: {yesterday_17} - {now}")

            except:
                received_at_naive = datetime.utcnow()
                print(f"Data maila: {received_at_naive}, filtrowana względem: {yesterday_17} - {now}")

            if received_at_naive < yesterday_17:
                break
            if yesterday_17 <= received_at_naive <= now:
                fetched.append({
                    "sent_from": from_,
                    "sent_to": to_,
                    "subject": subject,
                    "content": body.strip(),
                    "received_at": received_at_naive,
                    "mail_id": message_id,
                })

        mail.logout()
        return fetched

    except Exception as e:
        print(f"Błąd podczas pobierania wiadomości: {e}")
        return []

def fetch_all_emails():
    from app.models import GmailCredentials, Email

    def extract_email(full: str) -> str:
        import re
        match = re.search(r'<([^>]+)>', full)
        return match.group(1) if match else full.strip()

    with get_session() as session:
        creds = session.query(GmailCredentials).all()
        for cred in creds:
            print(f"🔑 Przetwarzam konto: {cred.email} (IMAP: {cred.imap_server}:{cred.imap_port})")
            emails = fetch_emails_from_imap(cred)
            for e in emails:
                email_obj = Email(
                    sent_from=extract_email(e["sent_from"]),
                    sent_to=extract_email(e["sent_to"]),
                    subject=e["subject"],
                    content=e["content"],
                    received_at=e["received_at"],
                    mail_id=e["mail_id"],
                    received_from=cred.email,
                )
                session.add(email_obj)
        session.commit()
