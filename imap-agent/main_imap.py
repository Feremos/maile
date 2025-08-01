import sys
import os   
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from imap_zapis import fetch_all_emails
from agent_ai import process_emails_with_openai

def main():
    print("Krok 1: Pobieranie wiadomości z IMAP...")
    fetch_all_emails()
    print("Wiadomości pobrane i zapisane do bazy.")
    

    print("Krok 2: Przetwarzanie wiadomości przez OpenAI...")
    process_emails_with_openai()
    print("Wiadomości przetworzone i zaktualizowane w bazie.")

    print("🎯 Zakończono!")

if __name__ == "__main__":
    main()
