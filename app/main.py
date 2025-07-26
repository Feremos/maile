import os
import re
import datetime
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Form, Depends, HTTPException, status, Cookie, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey
from jose import JWTError, jwt
from passlib.context import CryptContext
from cryptography.fernet import Fernet
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from fastapi import Query
import asyncio
from enum import Enum

from .db import SessionLocal, engine
from .models import Base, User, Email, GmailCredentials, ScheduledEmail

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
FERNET_KEY = os.getenv("FERNET_KEY")

if not SECRET_KEY or not FERNET_KEY:
    raise RuntimeError("Brak kluczy .env")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
fernet = Fernet(FERNET_KEY.encode())



Base.metadata.create_all(bind=engine)
app = FastAPI()
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

class EmailStatus(str, Enum):
    PENDING = "pending"
    SENT = "sent"
    CANCELLED = "cancelled"

class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_password_hash(password): 
    return pwd_context.hash(password)

def verify_password(plain, hashed): 
    return pwd_context.verify(plain, hashed)

def encrypt_password(password): 
    return fernet.encrypt(password.encode()).decode()

def decrypt_password(token): 
    return fernet.decrypt(token.encode()).decode()

def get_user(db, email: str):
    return db.query(User).filter(User.login_app == email).first()

def extract_email(full: str):
    match = re.search(r'<([^>]+)>', full)
    return match.group(1) if match else full.strip()

def get_emails_for_user(db: Session, user: User):
    visible_addresses = [cred.email for cred in user.selected_gmail_credentials]
    if not visible_addresses:
        return []
    return (
        db.query(Email)
        .filter(Email.sent_to.in_(visible_addresses), Email.is_archived == False)
        .order_by(Email.received_at.desc())
        .all()
    )

def get_current_user_from_cookie(db: Session = Depends(get_db), user_email: str = Cookie(None)):
    if not user_email:
        raise HTTPException(status_code=401, detail="Nie jesteś zalogowany")
    user = get_user(db, user_email)
    if not user:
        raise HTTPException(status_code=401, detail="Nieprawidłowy użytkownik")
    return user

def get_pending_emails_for_user(db: Session, user: User):
    """Pobierz oczekujące emaile dla użytkownika"""
    visible_addresses = [cred.email for cred in user.selected_gmail_credentials]
    if not visible_addresses:
        return []
    
    return (
        db.query(ScheduledEmail)
        .join(Email, ScheduledEmail.email_id == Email.id)
        .filter(
            Email.sent_to.in_(visible_addresses),
            ScheduledEmail.status == EmailStatus.PENDING
        )
        .all()
    )

async def send_delayed_email(scheduled_email_id: int, delay_minutes: int = 5):
    """Funkcja do wysłania emaila po opóźnieniu"""
    # Czekaj określony czas
    await asyncio.sleep(delay_minutes * 60)
    
    db = SessionLocal()
    try:
        # Pobierz zaplanowany email z bazy
        scheduled_email = db.query(ScheduledEmail).filter(ScheduledEmail.id == scheduled_email_id).first()
        if not scheduled_email or scheduled_email.status != EmailStatus.PENDING:
            return
        
        # Pobierz oryginalny email
        email = db.query(Email).filter(Email.id == scheduled_email.email_id).first()
        if not email:
            scheduled_email.status = EmailStatus.CANCELLED
            db.commit()
            return
        
        sent_to_clean = email.sent_to.strip().lower()
        credentials = db.query(GmailCredentials).filter(GmailCredentials.login.ilike(sent_to_clean)).first()
        if not credentials:
            scheduled_email.status = EmailStatus.CANCELLED
            db.commit()
            return
        
        recipient = extract_email(email.sent_from)
        msg = EmailMessage()
        msg["Subject"] = f"Odpowiedź: {email.subject}"
        msg["From"] = credentials.login
        msg["To"] = recipient
        msg.set_content(scheduled_email.reply_text)
        
        with smtplib.SMTP(credentials.smtp_server, credentials.smtp_port) as server:
            if credentials.use_tls:
                server.starttls()
            decrypted_password = decrypt_password(credentials.encrypted_password)
            server.login(credentials.login, decrypted_password)
            server.send_message(msg)
        
        # Oznacz email jako wysłany i zarchiwizowany
        email.is_archived = True
        scheduled_email.status = EmailStatus.SENT
        db.commit()
        
    except Exception as e:
        print(f"Błąd wysyłania emaila: {e}")
        if 'scheduled_email' in locals():
            scheduled_email.status = EmailStatus.CANCELLED
            db.commit()
    finally:
        db.close()

async def check_and_send_pending_emails():
    """Background task sprawdzający i wysyłający zaległe emaile"""
    while True:
        db = SessionLocal()
        try:
            # Znajdź emaile które powinny być już wysłane
            now = datetime.datetime.utcnow()
            overdue_emails = (
                db.query(ScheduledEmail)
                .filter(
                    ScheduledEmail.status == EmailStatus.PENDING,
                    ScheduledEmail.scheduled_time <= now
                )
                .all()
            )
            
            for scheduled_email in overdue_emails:
                # Wysłij natychmiast bez dodatkowego opóźnienia
                asyncio.create_task(send_delayed_email(scheduled_email.id, 0))
            
        except Exception as e:
            print(f"Błąd sprawdzania oczekujących emaili: {e}")
        finally:
            db.close()
        
        # Sprawdzaj co minutę
        await asyncio.sleep(60)

@app.on_event("startup")
async def startup_event():
    """Uruchom background task przy starcie aplikacji"""
    asyncio.create_task(check_and_send_pending_emails())

from fastapi import Path

@app.get("/category/{category_name}", response_class=HTMLResponse)
def read_emails_by_category(
    category_name: str,
    request: Request,
    selected_email: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_from_cookie)
):
    visible_addresses = [cred.email for cred in current_user.selected_gmail_credentials]

    # Jeśli wybrano konkretny email i jest on w widocznych
    if selected_email and selected_email not in visible_addresses:
        emails = []
    else:
        query = db.query(Email).filter(
            Email.sent_to.in_(visible_addresses),
            Email.classification == category_name,
            Email.is_archived == False,
        )
        if selected_email:
            query = query.filter(Email.sent_to == selected_email)
        emails = query.order_by(Email.received_at.desc()).all()

    pending_emails = get_pending_emails_for_user(db, current_user)

    return templates.TemplateResponse("index.html", {
        "request": request,
        "emails": emails,
        "user": current_user,
        "user_visible_emails": visible_addresses,
        "active_category": category_name,
        "selected_email": selected_email,
        "pending_emails": pending_emails
    })

@app.get("/archiwum", response_class=HTMLResponse)
def read_archived_emails(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_from_cookie)
):
    visible_addresses = [cred.email for cred in current_user.selected_gmail_credentials]
    if not visible_addresses:
        emails = []
    else:
        emails = (
            db.query(Email)
            .filter(
                Email.sent_to.in_(visible_addresses),
                Email.is_archived == True,
            )
            .order_by(Email.received_at.desc())
            .all()
        )
    
    pending_emails = get_pending_emails_for_user(db, current_user)
    
    return templates.TemplateResponse("index.html", {
        "request": request,
        "emails": emails,
        "user": current_user,
        "user_visible_emails": visible_addresses,
        "active_category": "archiwum",
        "pending_emails": pending_emails
    })

from fastapi import Query

@app.get("/", response_class=HTMLResponse)
def read_emails(
    request: Request,
    selected_email: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_from_cookie)
):
    visible_emails = [cred.email for cred in current_user.selected_gmail_credentials]

    if selected_email:
        if selected_email in visible_emails:
            emails = (
                db.query(Email)
                .filter(Email.sent_to == selected_email, Email.is_archived == False)
                .order_by(Email.received_at.desc())
                .all()
            )
        else:
            # Jeśli ktoś wpisze email spoza listy – zwróć nic
            emails = []
    else:
        emails = (
            db.query(Email)
            .filter(Email.sent_to.in_(visible_emails), Email.is_archived == False)
            .order_by(Email.received_at.desc())
            .all()
        )

    pending_emails = get_pending_emails_for_user(db, current_user)

    return templates.TemplateResponse("index.html", {
        "request": request,
        "emails": emails,
        "user": current_user,
        "user_visible_emails": visible_emails,
        "selected_email": selected_email,
        "pending_emails": pending_emails
    })

@app.post("/add_email_account", response_class=HTMLResponse)
def add_email_account(
    request: Request,
    email_address: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_from_cookie),
):
    email_address = email_address.strip().lower()

    credential = db.query(GmailCredentials).filter_by(email=email_address).first()
    if not credential:
        return templates.TemplateResponse("index.html", {
            "request": request,
            "emails": get_emails_for_user(db, current_user),
            "user": current_user,
            "user_visible_emails": [c.email for c in current_user.selected_gmail_credentials],
            "add_email_error": f"Adres {email_address} nie istnieje w gmail_credentials.",
            "pending_emails": get_pending_emails_for_user(db, current_user)
        })

    if credential in current_user.selected_gmail_credentials:
        return templates.TemplateResponse("index.html", {
            "request": request,
            "emails": get_emails_for_user(db, current_user),
            "user": current_user,
            "user_visible_emails": [c.email for c in current_user.selected_gmail_credentials],
            "add_email_error": f"Adres {email_address} już jest dodany.",
            "pending_emails": get_pending_emails_for_user(db, current_user)
        })

    current_user.selected_gmail_credentials.append(credential)
    db.commit()

    return templates.TemplateResponse("index.html", {
        "request": request,
        "emails": get_emails_for_user(db, current_user),
        "user": current_user,
        "user_visible_emails": [c.email for c in current_user.selected_gmail_credentials],
        "add_email_message": f"Adres {email_address} został dodany.",
        "pending_emails": get_pending_emails_for_user(db, current_user)
    })

@app.post("/webhook")
async def receive_email(
    user_email: str = Form(...),
    subject: str = Form(...),
    content: str = Form(...),
    classification: str = Form(...),
    suggested_reply: str = Form(...),
    summary: str = Form(None),
    mail_id: str = Form(None),
    thread_id: str = Form(None),
    received_from: str = Form(None),
    db: Session = Depends(get_db),
):
    credential = db.query(GmailCredentials).filter(GmailCredentials.login.ilike(user_email)).first()
    if not credential:
        raise HTTPException(status_code=400, detail="Nie znaleziono danych konta Gmail dla tego adresu")
    email = Email(
        sent_to=user_email.lower(),
        sent_from=received_from,
        subject=subject,
        content=content,
        classification=classification,
        suggested_reply=suggested_reply,
        summary=summary,
        mail_id=mail_id,
        thread_id=thread_id,
        received_from=received_from,
    )
    db.add(email)
    db.commit()
    db.refresh(email)
    return {"status": "ok", "id": email.id}

@app.post("/reply")
def schedule_reply(
    background_tasks: BackgroundTasks,
    email_id: int = Form(...), 
    reply_text: str = Form(...), 
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_current_user_from_cookie)
):
    email = db.query(Email).filter(Email.id == email_id).first()
    if not email:
        raise HTTPException(status_code=404, detail="Email nie znaleziony")
    
    # Zapisz zaplanowany email w bazie danych
    scheduled_email = ScheduledEmail(
        email_id=email_id,
        reply_text=reply_text,
        scheduled_time=datetime.datetime.utcnow() + datetime.timedelta(minutes=5),
        status=EmailStatus.PENDING
    )
    db.add(scheduled_email)
    db.commit()
    db.refresh(scheduled_email)
    
    # Zaplanuj wysłanie emaila w tle
    background_tasks.add_task(send_delayed_email, scheduled_email.id, 5)
    
    return RedirectResponse(url="/", status_code=302)

@app.post("/cancel_reply/{scheduled_email_id}")
def cancel_reply(
    scheduled_email_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_from_cookie)
):
    scheduled_email = db.query(ScheduledEmail).filter(ScheduledEmail.id == scheduled_email_id).first()
    if scheduled_email and scheduled_email.status == EmailStatus.PENDING:
        scheduled_email.status = EmailStatus.CANCELLED
        db.commit()
    
    return RedirectResponse(url="/", status_code=302)

@app.get("/pending_emails")
def get_pending_emails_api(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_from_cookie)
):
    pending_emails = get_pending_emails_for_user(db, current_user)
    result = {}
    for scheduled_email in pending_emails:
        email = db.query(Email).filter(Email.id == scheduled_email.email_id).first()
        if email:
            result[scheduled_email.id] = {
                "scheduled_time": scheduled_email.scheduled_time.isoformat(),
                "reply_text": scheduled_email.reply_text[:100] + "..." if len(scheduled_email.reply_text) > 100 else scheduled_email.reply_text,
                "subject": email.subject,
                "email_id": email.id
            }
    return result

@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login", response_class=HTMLResponse)
def login_post(request: Request, db: Session = Depends(get_db), email: str = Form(...), password: str = Form(...)):
    user = get_user(db, email)
    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Nieprawidłowy email lub hasło"})
    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(key="user_email", value=user.login_app, httponly=True)
    return response

@app.get("/register", response_class=HTMLResponse)
def register_get(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register", response_class=HTMLResponse)
def register_post(
    request: Request,
    login_app: str = Form(...),
    password: str = Form(...),
):
    db: Session = SessionLocal()
    existing_user = db.query(User).filter_by(login_app=login_app).first()

    if existing_user:
        return templates.TemplateResponse(
            "register.html",
            {
                "request": request,
                "error": "Użytkownik o tym loginie już istnieje."
            }
        )

    hashed_pw = pwd_context.hash(password)
    new_user = User(login_app=login_app, hashed_password=hashed_pw)
    db.add(new_user)
    db.commit()
    db.close()

    response = RedirectResponse(url="/login", status_code=303)
    return response

@app.get("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("user_email")
    return response