import sys
import os   
from db_agent import get_session
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from openai import OpenAI
from app.models import Email
from dotenv import load_dotenv
load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

PROMPT_TEMPLATE = """
Przeanalizuj poniższą treść e-maila i zwróć odpowiedź w dokładnie takim formacie:

Kategoria: <faktura | reklamacja | oferta | rezygnacja | brak klasyfikacji>
Odpowiedź: <krótka, uprzejma odpowiedź'>
Streszczenie: <2-3 zdania podsumowania, konkretnie czego dotyczy e-mail>

---

Treść e-maila:
"{content}"
"""


def extract_section(name, text):
    name = name.lower()
    for line in text.splitlines():
        if line.lower().startswith(name):
            return line.split(":", 1)[1].strip()
    return ""

def process_emails_with_openai():
    with get_session() as session:
        emails = session.query(Email).filter(Email.classification.is_(None)).all()

        for email in emails:
            prompt = PROMPT_TEMPLATE.format(content=email.content)
            try:
                response = client.chat.completions.create(
                    model="gpt-4o",
                    messages=[
                        {"role": "system", "content": "Jesteś asystentem klienta. Odpowiadasz na maile profesjonalnie."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.3
                )

                content = response.choices[0].message.content.strip()

                email.classification = extract_section("kategoria", content).lower() or "brak klasyfikacji"
                reply = extract_section("Odpowiedź", content)
                summary = extract_section("streszczenie", content)
                print (reply)
                print(content)
                email.suggested_reply = reply if reply else "brak odpowiedzi"
                email.summary = summary
                print(f"Przetworzono e-mail {email.id}: Kategoria: {email.classification}, Odpowiedź: {email.suggested_reply}, Streszczenie: {email.summary}")
            except Exception as e:
                print(f"Błąd przy analizie e-maila {email.id}: {e}")
                

        session.commit()
