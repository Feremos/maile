import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Import aplikacji
from app.main import app, get_db, get_password_hash, verify_password, encrypt_password, decrypt_password
from app.main import extract_email, get_emails_for_user, get_pending_emails_for_user, send_delayed_email
from app.main import EmailStatus
from app.models import Base, User, Email, GmailCredentials, ScheduledEmail

# Testowa baza danych w pamięci
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Override dependency
def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(scope="function")
def db_session():
    """Fixture dla sesji bazy danych"""
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    yield db
    db.close()
    Base.metadata.drop_all(bind=engine)

@pytest.fixture
def client():
    """Fixture dla klienta testowego"""
    return TestClient(app)

@pytest.fixture
def test_user(db_session):
    """Fixture dla testowego użytkownika"""
    user = User(
        login_app="test1@gmail.com",
        hashed_password=get_password_hash("test")
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user

@pytest.fixture
def test_gmail_credentials(db_session):
    """Fixture dla testowych danych Gmail"""
    creds = GmailCredentials(
        email="test@gmail.com",
        login="test@gmail.com",
        encrypted_password=encrypt_password("gmailpassword"),
        smtp_server="smtp.gmail.com",
        smtp_port=587,
        use_tls=True
    )
    db_session.add(creds)
    db_session.commit()
    db_session.refresh(creds)
    return creds

@pytest.fixture
def test_email(db_session):
    """Fixture dla testowego emaila"""
    email = Email(
        sent_from="sender@example.com",
        sent_to="test@gmail.com",
        subject="Test Subject",
        content="Test content",
        summary="Test summary",
        classification="work",
        suggested_reply="Test reply",
        received_at=datetime.utcnow()
    )
    db_session.add(email)
    db_session.commit()
    db_session.refresh(email)
    return email

@pytest.fixture
def authenticated_client(client, test_user):
    """Fixture dla zalogowanego klienta"""
    client.cookies.set("user_email", test_user.login_app)
    return client

class TestUtilityFunctions:
    """Testy funkcji pomocniczych"""
    
    def test_password_hashing(self):
        """Test hashowania haseł"""
        password = "testpassword123"
        hashed = get_password_hash(password)
        
        assert hashed != password
        assert verify_password(password, hashed)
        assert not verify_password("wrongpassword", hashed)
    
    def test_password_encryption(self):
        """Test szyfrowania haseł"""
        password = "mysecretpassword"
        encrypted = encrypt_password(password)
        decrypted = decrypt_password(encrypted)
        
        assert encrypted != password
        assert decrypted == password
    
    def test_extract_email(self):
        """Test wyciągania adresu email"""
        # Test z nawiasami kątowymi
        full_email = "John Doe <john@example.com>"
        assert extract_email(full_email) == "john@example.com"
        
        # Test bez nawiasów
        simple_email = "john@example.com"
        assert extract_email(simple_email) == "john@example.com"
        
        # Test z spacjami
        spaced_email = "  john@example.com  "
        assert extract_email(spaced_email) == "john@example.com"

class TestAuthentication:
    """Testy autentykacji"""
    
    def test_register_success(self, client):
        """Test udanej rejestracji"""
        response = client.post("/register", data={
            "login_app": "newuser@example.com",
            "password": "newpassword123"
        })
        assert response.status_code == 303
        assert response.headers["location"] == "/login"
    
    def test_register_duplicate_user(self, client, test_user):
        """Test rejestracji z istniejącym użytkownikiem"""
        response = client.post("/register", data={
            "login_app": test_user.login_app,
            "password": "somepassword"
        })
        assert response.status_code == 200
        assert "Użytkownik o tym loginie już istnieje" in response.text
    
    def test_login_success(self, client, test_user):
        """Test udanego logowania"""
        response = client.post("/login", data={
            "email": test_user.login_app,
            "password": "testpassword"
        })
        assert response.status_code == 302
        assert "user_email" in response.cookies
    
    def test_login_failure(self, client, test_user):
        """Test nieudanego logowania"""
        response = client.post("/login", data={
            "email": test_user.login_app,
            "password": "wrongpassword"
        })
        assert response.status_code == 200
        assert "Nieprawidłowy email lub hasło" in response.text
    

class TestEmailManagement:
    """Testy zarządzania emailami"""
    
    def test_get_emails_for_user(self, db_session, test_user, test_gmail_credentials, test_email):
        """Test pobierania emaili dla użytkownika"""
        # Dodaj credentials do użytkownika
        test_user.selected_gmail_credentials.append(test_gmail_credentials)
        db_session.commit()
        
        emails = get_emails_for_user(db_session, test_user)
        assert len(emails) == 1
        assert emails[0].id == test_email.id
    
    def test_get_emails_with_category_filter(self, db_session, test_user, test_gmail_credentials):
        """Test filtrowania emaili po kategorii"""
        test_user.selected_gmail_credentials.append(test_gmail_credentials)
        
        # Dodaj emaile z różnymi kategoriami
        email1 = Email(sent_to="test@gmail.com", classification="work", is_archived=False)
        email2 = Email(sent_to="test@gmail.com", classification="personal", is_archived=False)
        email3 = Email(sent_to="test@gmail.com", classification="work", is_archived=True)
        
        db_session.add_all([email1, email2, email3])
        db_session.commit()
        
        # Test filtrowania po kategorii work
        work_emails = get_emails_for_user(db_session, test_user, category="work")
        assert len(work_emails) == 1
        assert work_emails[0].classification == "work"
        assert not work_emails[0].is_archived
        
        # Test filtrowania archiwum
        archived_emails = get_emails_for_user(db_session, test_user, category="archiwum")
        assert len(archived_emails) == 1
        assert archived_emails[0].is_archived
    
    def test_get_emails_api_json(self, authenticated_client, db_session, test_user, test_gmail_credentials, test_email):
        """Test API endpoint dla emaili z JSON response"""
        test_user.selected_gmail_credentials.append(test_gmail_credentials)
        db_session.commit()
        
        response = authenticated_client.get("/api/emails", headers={"accept": "application/json"})
        assert response.status_code == 200
        
        data = response.json()
        assert "emails" in data
        assert "userVisibleEmails" in data
        assert "pendingEmails" in data
        assert len(data["emails"]) == 1
        assert data["emails"][0]["subject"] == "Test Subject"
    
    def test_add_email_account_api(self, authenticated_client, db_session, test_user, test_gmail_credentials):
        """Test dodawania konta email przez API"""
        response = authenticated_client.post("/api/add_email_account", data={
            "email_address": test_gmail_credentials.email
        })
        assert response.status_code == 200
        
        data = response.json()
        assert data["status"] == "success"
        
        # Sprawdź czy konto zostało dodane
        db_session.refresh(test_user)
        assert test_gmail_credentials in test_user.selected_gmail_credentials
    
    def test_add_nonexistent_email_account(self, authenticated_client, test_user):
        """Test dodawania nieistniejącego konta email"""
        response = authenticated_client.post("/api/add_email_account", data={
            "email_address": "nonexistent@example.com"
        })
        assert response.status_code == 400
        assert "nie istnieje w gmail_credentials" in response.json()["detail"]

class TestEmailReplies:
    """Testy odpowiedzi na emaile"""
    
    
    def test_schedule_reply_unauthorized_email(self, authenticated_client, db_session, test_user, test_email):
        """Test planowania odpowiedzi na email bez dostępu"""
        response = authenticated_client.post("/api/reply", data={
            "email_id": test_email.id,
            "reply_text": "This should fail"
        })
        assert response.status_code == 403
        assert "Brak dostępu do tego emaila" in response.json()["detail"]
    
    def test_cancel_reply_api(self, authenticated_client, db_session, test_user, test_gmail_credentials, test_email):
        """Test anulowania odpowiedzi przez API"""
        test_user.selected_gmail_credentials.append(test_gmail_credentials)
        
        # Utwórz zaplanowany email
        scheduled_email = ScheduledEmail(
            email_id=test_email.id,
            reply_text="Test reply",
            scheduled_time=datetime.utcnow() + timedelta(minutes=5),
            status=EmailStatus.PENDING
        )
        db_session.add(scheduled_email)
        db_session.commit()
        db_session.refresh(scheduled_email)
        
        response = authenticated_client.post(f"/api/cancel_reply/{scheduled_email.id}")
        assert response.status_code == 200
        
        data = response.json()
        assert data["status"] == "success"
        
        # Sprawdź czy status został zmieniony
        db_session.refresh(scheduled_email)
        assert scheduled_email.status == EmailStatus.CANCELLED
    
    def test_get_pending_emails_for_user(self, db_session, test_user, test_gmail_credentials, test_email):
        """Test pobierania oczekujących emaili dla użytkownika"""
        test_user.selected_gmail_credentials.append(test_gmail_credentials)
        
        # Utwórz zaplanowany email
        scheduled_email = ScheduledEmail(
            email_id=test_email.id,
            reply_text="Test reply",
            scheduled_time=datetime.utcnow() + timedelta(minutes=5),
            status=EmailStatus.PENDING
        )
        db_session.add(scheduled_email)
        db_session.commit()
        
        pending_emails = get_pending_emails_for_user(db_session, test_user)
        assert len(pending_emails) == 1
        assert pending_emails[0].id == scheduled_email.id

class TestWebhook:
    """Testy webhook'a do odbierania emaili"""
    
    def test_receive_email_webhook(self, client, db_session, test_gmail_credentials):
        """Test odbierania emaila przez webhook"""
        response = client.post("/webhook", data={
            "user_email": test_gmail_credentials.login,
            "subject": "Webhook Test Subject",
            "content": "Webhook test content",
            "classification": "personal",
            "suggested_reply": "Webhook test reply",
            "summary": "Webhook test summary",
            "mail_id": "test_mail_id",
            "thread_id": "test_thread_id",
            "received_from": "webhook@example.com"
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "id" in data
        
        # Sprawdź czy email został zapisany w bazie
        email = db_session.query(Email).filter_by(subject="Webhook Test Subject").first()
        assert email is not None
        assert email.classification == "personal"
        assert email.sent_to == test_gmail_credentials.login.lower()
    
    def test_receive_email_webhook_invalid_user(self, client):
        """Test webhook'a z nieistniejącym użytkownikiem"""
        response = client.post("/webhook", data={
            "user_email": "nonexistent@example.com",
            "subject": "Test Subject",
            "content": "Test content",
            "classification": "personal",
            "suggested_reply": "Test reply"
        })
        
        assert response.status_code == 400
        assert "Nie znaleziono danych konta Gmail" in response.json()["detail"]

class TestAsyncFunctions:
    """Testy funkcji asynchronicznych"""
    
    @pytest.mark.asyncio
    async def test_send_delayed_email_success(self, db_session, test_gmail_credentials, test_email):
        """Test wysyłania opóźnionego emaila"""
        # Utwórz zaplanowany email
        scheduled_email = ScheduledEmail(
            email_id=test_email.id,
            reply_text="Test delayed reply",
            scheduled_time=datetime.utcnow(),
            status=EmailStatus.PENDING
        )
        db_session.add(scheduled_email)
        db_session.commit()
        scheduled_email_id = scheduled_email.id
        
        # Mock SMTP
        with patch('smtplib.SMTP') as mock_smtp:
            mock_server = MagicMock()
            mock_smtp.return_value.__enter__.return_value = mock_server
            
            # Wywołaj funkcję z 0 minut opóźnienia
            await send_delayed_email(scheduled_email_id, 0)
            
            # Sprawdź czy SMTP został wywołany
            mock_smtp.assert_called_once()
            mock_server.starttls.assert_called_once()
            mock_server.login.assert_called_once()
            mock_server.send_message.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_send_delayed_email_nonexistent(self):
        """Test wysyłania opóźnionego emaila dla nieistniejącego ID"""
        # Nie powinno rzucać wyjątku
        await send_delayed_email(99999, 0)

class TestHTMLEndpoints:
    """Testy endpointów HTML"""
    
    def test_home_page_authenticated(self, authenticated_client, db_session, test_user, test_gmail_credentials, test_email):
        """Test strony głównej dla zalogowanego użytkownika"""
        test_user.selected_gmail_credentials.append(test_gmail_credentials)
        db_session.commit()
        
        response = authenticated_client.get("/")
        assert response.status_code == 200
        assert "Test Subject" in response.text
    
    def test_home_page_unauthenticated(self, client):
        """Test strony głównej dla niezalogowanego użytkownika"""
        response = client.get("/")
        assert response.status_code == 401
    
    def test_category_page(self, authenticated_client, db_session, test_user, test_gmail_credentials):
        """Test strony kategorii"""
        test_user.selected_gmail_credentials.append(test_gmail_credentials)
        
        # Dodaj email z kategorią work
        email = Email(sent_to="test@gmail.com", classification="work", subject="Work Email")
        db_session.add(email)
        db_session.commit()
        
        response = authenticated_client.get("/category/work")
        assert response.status_code == 200
        assert "Work Email" in response.text
    
    def test_archive_page(self, authenticated_client, db_session, test_user, test_gmail_credentials):
        """Test strony archiwum"""
        test_user.selected_gmail_credentials.append(test_gmail_credentials)
        
        # Dodaj zarchiwizowany email
        email = Email(sent_to="test@gmail.com", subject="Archived Email", is_archived=True)
        db_session.add(email)
        db_session.commit()
        
        response = authenticated_client.get("/archiwum")
        assert response.status_code == 200
        assert "Archived" in response.text

class TestErrorHandling:
    """Testy obsługi błędów"""
    
    def test_reply_to_nonexistent_email(self, authenticated_client):
        """Test odpowiedzi na nieistniejący email"""
        response = authenticated_client.post("/api/reply", data={
            "email_id": 99999,
            "reply_text": "This should fail"
        })
        assert response.status_code == 404
        assert "Email nie znaleziony" in response.json()["detail"]
    
    def test_cancel_nonexistent_reply(self, authenticated_client):
        """Test anulowania nieistniejącej odpowiedzi"""
        response = authenticated_client.post("/api/cancel_reply/99999")
        assert response.status_code == 404
        assert "Zaplanowany email nie znaleziony" in response.json()["detail"]
    
    def test_cancel_already_sent_reply(self, authenticated_client, db_session, test_user, test_gmail_credentials, test_email):
        """Test anulowania już wysłanej odpowiedzi"""
        test_user.selected_gmail_credentials.append(test_gmail_credentials)
        
        # Utwórz już wysłany email
        scheduled_email = ScheduledEmail(
            email_id=test_email.id,
            reply_text="Already sent",
            scheduled_time=datetime.utcnow(),
            status=EmailStatus.SENT
        )
        db_session.add(scheduled_email)
        db_session.commit()
        
        response = authenticated_client.post(f"/api/cancel_reply/{scheduled_email.id}")
        assert response.status_code == 400
        assert "Nie można anulować tego emaila" in response.json()["detail"]

# Konfiguracja pytest
if __name__ == "__main__":
    pytest.main([__file__, "-v"])