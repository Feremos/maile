import sys
import os   
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import imaplib
import email
from email.header import decode_header
from datetime import datetime
from app.db import get_session
from app.models import GmailCredentials, Email

from cryptography.fernet import Fernet


from dotenv import load_dotenv

load_dotenv()

fernet = Fernet(os.getenv("FERNET_KEY"))

def decode_mime_words(s):
    decoded = decode_header(s)
    return ''.join([t[0].decode(t[1] or 'utf-8') if isinstance(t[0], bytes) else t[0] for t in decoded if t[0]])

def fetch_emails_from_imap(creds: GmailCredentials):
    try:
        mail = imaplib.IMAP4_SSL(creds.imap_server, creds.imap_port)
        decrypted_password = fernet.decrypt(creds.encrypted_password.encode()).decode()
        mail.login(creds.login, decrypted_password)

        mail.select("inbox")

        status, messages = mail.search(None, "UNSEEN")
        email_ids = messages[0].split()

        fetched = []

        
        for eid in email_ids[-1:]:  #   only fetch the latest email
            _, msg_data = mail.fetch(eid, "(BODY.PEEK[])")
            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)

            subject = decode_mime_words(msg["Subject"] or "")
            from_ = msg.get("From", "")
            to_ = msg.get("To", "")
            date_raw = msg.get("Date")
            message_id = msg.get("Message-ID")

            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain" and not part.get("Content-Disposition"):
                        try:
                            body = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8")
                            break
                        except:
                            continue
            else:
                try:
                    body = msg.get_payload(decode=True).decode(msg.get_content_charset() or "utf-8")
                except:
                    body = msg.get_payload()

            try:
                received_at = datetime.strptime(date_raw[:31], "%a, %d %b %Y %H:%M:%S %z")
            except:
                received_at = datetime.utcnow()

            fetched.append({
                "sent_from": from_,
                "sent_to": to_,
                "subject": subject,
                "content": body.strip(),
                "received_at": received_at,
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
            print(f"🔑 Przetwarzam konto: {cred.email} (IMAP: {cred.imap_server}:{cred.imap_port}, hasło :{cred.encrypted_password})")
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

