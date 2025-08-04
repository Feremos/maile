import os
import re
import datetime
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Form, Depends, HTTPException, status, Cookie, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
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
from datetime import timedelta
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import RedirectResponse
from sqlalchemy import or_
# to run : uvicorn app.main:app --reload

from .db import SessionLocal, engine
from .models import Base, User, Email, GmailCredentials, ScheduledEmail



load_dotenv()
ADMIN_KEY = os.getenv("ADMIN_KEY")
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

def get_emails_for_user(db: Session, user: User, category: str = None, selected_email: str = None):
    visible_addresses = [extract_email(cred.email) for cred in user.selected_gmail_credentials]

    if not visible_addresses:
        return []
    
    query = db.query(Email).filter(Email.sent_to.in_(visible_addresses))
    
    # Filtruj po kategorii
    if category == "archiwum":
        query = query.filter(Email.is_archived == True)
    elif category:
        query = query.filter(Email.classification == category, Email.is_archived == False)
    else:
        query = query.filter(Email.is_archived == False)
    
    # Filtruj po wybranym emailu
    if selected_email and selected_email in visible_addresses:
        query = query.filter(Email.sent_to == selected_email)
    
    return query.order_by(Email.received_at.desc()).all()



ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # tydzień ważności

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")


def get_current_user_from_cookie(
    db: Session = Depends(get_db),
    token: Optional[str] = Cookie(None, alias="access_token")
):
    if not token:
        raise HTTPException(status_code=401, detail="Brak tokenu uwierzytelniającego")
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        user_email = payload.get("sub")
        if not user_email:
            raise HTTPException(status_code=401, detail="Token nie zawiera adresu email")
    except JWTError:
        raise HTTPException(status_code=401, detail="Nieprawidłowy token")
    
    user = get_user(db, user_email)
    if not user:
        raise HTTPException(status_code=401, detail="Użytkownik nie istnieje")
    return user


class AuthRedirectMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        token = request.cookies.get("access_token")
        path = request.url.path
        # Sprawdź czy URL wymaga logowania
        protected_paths = ["/" "/dashboard", "/emails",""]
        if any(request.url.path.startswith(p) for p in protected_paths):
            if not token:
                if path != "/login":
                    return RedirectResponse(url="/login", status_code=302)
        return await call_next(request)

app.add_middleware(AuthRedirectMiddleware)


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

# ===== NOWE API ENDPOINTY =====

@app.get("/api/emails")
async def get_emails_api(
    request: Request,
    category: Optional[str] = Query(None),
    selected_email: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_from_cookie)
):
    """API endpoint do pobierania emaili w formacie JSON"""
    emails = get_emails_for_user(db, current_user, category, selected_email)
    
    # Konwertuj emaile do słowników
    emails_dict = []
    for email in emails:
        emails_dict.append({
            "id": email.id,
            "sent_from": email.sent_from,
            "sent_to": email.sent_to,
            "subject": email.subject,
            "content": email.content,
            "summary": email.summary,
            "classification": email.classification,
            "suggested_reply": email.suggested_reply,
            "received_at": email.received_at.isoformat() if email.received_at else None,
            "is_archived": email.is_archived
        })
    
    pending_emails = get_pending_emails_for_user(db, current_user)
    
    # Konwertuj pending_emails do słowników
    pending_dict = []
    for pe in pending_emails:
        pending_dict.append({
            "id": pe.id,
            "email_id": pe.email_id,
            "reply_text": pe.reply_text,
            "scheduled_time": pe.scheduled_time.isoformat(),
            "status": pe.status
        })
    
    return JSONResponse({
        "emails": emails_dict,
        "userVisibleEmails": [cred.email for cred in current_user.selected_gmail_credentials],
        "pendingEmails": pending_dict,
        "activeCategory": category or "",
        "selectedEmail": selected_email or ""
    })

async def get_emails_html(
    request: Request,
    category: Optional[str] = None,
    selected_email: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_from_cookie)
):
    """Funkcja pomocnicza do renderowania HTML (dla pierwszego załadowania)"""
    emails = get_emails_for_user(db, current_user, category, selected_email)
    pending_emails = get_pending_emails_for_user(db, current_user)
    
    return templates.TemplateResponse("index.html", {
        "request": request,
        "emails": emails,
        "user": current_user,
        "user_visible_emails": [cred.email for cred in current_user.selected_gmail_credentials],
        "active_category": category or "",
        "selected_email": selected_email or "",
        "pending_emails": pending_emails
    })

@app.post("/api/reply")
async def schedule_reply_api(
    background_tasks: BackgroundTasks,
    email_id: int = Form(...), 
    reply_text: str = Form(...), 
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_current_user_from_cookie)
):
    """API endpoint do planowania odpowiedzi"""
    email = db.query(Email).filter(Email.id == email_id).first()
    if not email:
        raise HTTPException(status_code=404, detail="Email nie znaleziony")
    
    # Sprawdź czy użytkownik ma dostęp do tego emaila
    visible_addresses = [cred.email for cred in current_user.selected_gmail_credentials]
    if email.sent_to not in visible_addresses:
        raise HTTPException(status_code=403, detail="Brak dostępu do tego emaila")
    
    # Zapisz zaplanowany email
    scheduled_email = ScheduledEmail(
        email_id=email_id,
        reply_text=reply_text,
        scheduled_time=datetime.datetime.utcnow() + datetime.timedelta(minutes=5),
        status=EmailStatus.PENDING
    )
    db.add(scheduled_email)

    # 💡 Nadpisujemy suggested_reply -> reply_text
    email.suggested_reply = reply_text  # lub "", jeśli pole nie dopuszcza NULL
    

    db.commit()
    db.refresh(scheduled_email)
    
    # Zaplanuj wysyłkę
    background_tasks.add_task(send_delayed_email, scheduled_email.id, 5)
    
    return JSONResponse({"status": "success", "message": "Odpowiedź została zaplanowana"})



@app.post("/api/archive_email/{email_id}")
async def archive_email_api(
    email_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_from_cookie)
):
    """API endpoint do archiwizacji emaila"""
    email = db.query(Email).filter(Email.id == email_id).first()
    
    if not email:
        raise HTTPException(status_code=404, detail="Email nie znaleziony")
    
    # Sprawdź czy użytkownik ma dostęp do tego emaila
    visible_addresses = [cred.email for cred in current_user.selected_gmail_credentials]
    if email.sent_to not in visible_addresses:
        raise HTTPException(status_code=403, detail="Brak dostępu do tego emaila")
    
    email.is_archived = True
    db.commit()
    
    return JSONResponse({"status": "success", "message": "Email został przeniesiony do archiwum"})

@app.post("/api/unarchive_email/{email_id}")
async def unarchive_email_api(
    email_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_from_cookie)
):
    """API endpoint do archiwizacji emaila"""
    email = db.query(Email).filter(Email.id == email_id).first()
    
    if not email:
        raise HTTPException(status_code=404, detail="Email nie znaleziony")
    
    # Sprawdź czy użytkownik ma dostęp do tego emaila
    visible_addresses = [cred.email for cred in current_user.selected_gmail_credentials]
    if email.sent_to not in visible_addresses:
        raise HTTPException(status_code=403, detail="Brak dostępu do tego emaila")
    
    email.is_archived = False
    db.commit()
    
    return JSONResponse({"status": "success", "message": "Email został odarchiwizowany"})

# Zmodyfikuj istniejący endpoint cancel_reply_api
@app.post("/api/cancel_reply/{scheduled_email_id}")
async def cancel_reply_api(
    scheduled_email_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_from_cookie)
):
    """API endpoint do anulowania odpowiedzi"""
    scheduled_email = db.query(ScheduledEmail).filter(ScheduledEmail.id == scheduled_email_id).first()
    
    if not scheduled_email:
        raise HTTPException(status_code=404, detail="Zaplanowany email nie znaleziony")
    
    # Sprawdź czy użytkownik ma dostęp do tego emaila
    email = db.query(Email).filter(Email.id == scheduled_email.email_id).first()
    if email:
        visible_addresses = [cred.email for cred in current_user.selected_gmail_credentials]
        if email.sent_to not in visible_addresses:
            raise HTTPException(status_code=403, detail="Brak dostępu do tego emaila")
    
    if scheduled_email.status == EmailStatus.PENDING:
        # Zapisz tekst odpowiedzi w suggested_reply przed anulowaniem
        if email:
            email.suggested_reply = scheduled_email.reply_text
            
        scheduled_email.status = EmailStatus.CANCELLED
        db.commit()
        return JSONResponse({"status": "success", "message": "Wysłanie emaila zostało anulowane"})
    else:
        raise HTTPException(status_code=400, detail="Nie można anulować tego emaila")
    
@app.post("/api/add_email_account")
async def add_email_account_api(
    email_address: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_from_cookie),
):
    """API endpoint do dodawania konta email"""
    email_address = email_address.strip().lower()

    credential = db.query(GmailCredentials).filter_by(email=email_address).first()
    if not credential:
        raise HTTPException(status_code=400, detail=f"Adres {email_address} nie istnieje w bazie danych")

    if credential in current_user.selected_gmail_credentials:
        raise HTTPException(status_code=400, detail=f"Adres {email_address} już jest dodany.")

    current_user.selected_gmail_credentials.append(credential)
    db.commit()

    return JSONResponse({"status": "success", "message": f"Adres {email_address} został dodany."})

@app.post("/api/remove_email_account")
async def remove_email_account_api(
    email_address: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_from_cookie),
):
    """API endpoint do usuwania konta email"""
    email_address = email_address.strip().lower()
    
    credential = db.query(GmailCredentials).filter_by(email=email_address).first()
    if not credential:
        raise HTTPException(status_code=400, detail=f"Adres {email_address} nie istnieje w gmail_credentials.")
    
    if credential not in current_user.selected_gmail_credentials:
        raise HTTPException(status_code=400, detail=f"Adres {email_address} nie jest przypisany do Twojego konta.")
    
    current_user.selected_gmail_credentials.remove(credential)
    db.commit()
    
    return JSONResponse({"status": "success", "message": f"Adres {email_address} został usunięty."})


# ===== ZACHOWANE ORYGINALNE ENDPOINTY HTML - POPRAWIONE =====

@app.get("/category/{category_name}", response_class=HTMLResponse)
async def read_emails_by_category(
    category_name: str,
    request: Request,
    selected_email: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_from_cookie)
):
    # Wywołaj bezpośrednio funkcję HTML zamiast API
    return await get_emails_html(request, category_name, selected_email, db, current_user)

@app.get("/archiwum", response_class=HTMLResponse)
async def read_archived_emails(
    request: Request,
    selected_email: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_from_cookie)
):
    # Wywołaj bezpośrednio funkcję HTML zamiast API
    return await get_emails_html(request, "archiwum", selected_email, db, current_user)

@app.get("/", response_class=HTMLResponse)
async def read_emails(
    request: Request,
    selected_email: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_from_cookie)
):
    # Wywołaj bezpośrednio funkcję HTML zamiast API
    return await get_emails_html(request, None, selected_email, db, current_user)

# Zachowane stare endpointy dla kompatybilności
@app.post("/add_email_account", response_class=HTMLResponse)
async def add_email_account(
    request: Request,
    email_address: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_from_cookie),
):
    try:
        await add_email_account_api(email_address, db, current_user)
        return templates.TemplateResponse("index.html", {
            "request": request,
            "emails": get_emails_for_user(db, current_user),
            "user": current_user,
            "user_visible_emails": [c.email for c in current_user.selected_gmail_credentials],
            "add_email_message": f"Adres {email_address} został dodany.",
            "pending_emails": get_pending_emails_for_user(db, current_user)
        })
    except HTTPException as e:
        return templates.TemplateResponse("index.html", {
            "request": request,
            "emails": get_emails_for_user(db, current_user),
            "user": current_user,
            "user_visible_emails": [c.email for c in current_user.selected_gmail_credentials],
            "add_email_error": e.detail,
            "pending_emails": get_pending_emails_for_user(db, current_user)
        })



@app.post("/reply")
async def schedule_reply(
    background_tasks: BackgroundTasks,
    email_id: int = Form(...), 
    reply_text: str = Form(...),
    send_immediately: str = Form("false"),  # Dodaj ten parametr
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_current_user_from_cookie)
):
    email = db.query(Email).filter(Email.id == email_id).first()
    if not email:
        raise HTTPException(status_code=404, detail="Email nie znaleziony")
    
    # Sprawdź czy użytkownik ma dostęp do tego emaila
    visible_addresses = [cred.email for cred in current_user.selected_gmail_credentials]
    if email.sent_to not in visible_addresses:
        raise HTTPException(status_code=403, detail="Brak dostępu do tego emaila")
    
    if send_immediately.lower() == "true":
        # Wyślij natychmiast
        try:
            sent_to_clean = email.sent_to.strip().lower()
            credentials = db.query(GmailCredentials).filter(GmailCredentials.login.ilike(sent_to_clean)).first()
            if not credentials:
                raise HTTPException(status_code=400, detail="Brak konfiguracji SMTP")
            
            recipient = extract_email(email.sent_from)
            msg = EmailMessage()
            msg["Subject"] = f"Odpowiedź: {email.subject}"
            msg["From"] = credentials.login
            msg["To"] = recipient
            msg.set_content(reply_text)
            
            with smtplib.SMTP(credentials.smtp_server, credentials.smtp_port) as server:
                if credentials.use_tls:
                    server.starttls()
                decrypted_password = decrypt_password(credentials.encrypted_password)
                server.login(credentials.login, decrypted_password)
                server.send_message(msg)
            
            # Oznacz email jako zarchiwizowany
            email.is_archived = True
            db.commit()
            
            return RedirectResponse(url="/", status_code=302)
            
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Błąd wysyłania emaila: {str(e)}")
    else:
        # Zaplanuj wysłanie za 5 minut (oryginalny kod)
        scheduled_email = ScheduledEmail(
            email_id=email_id,
            reply_text=reply_text,
            scheduled_time=datetime.datetime.utcnow() + datetime.timedelta(minutes=5),
            status=EmailStatus.PENDING
        )
        db.add(scheduled_email)
        db.commit()
        db.refresh(scheduled_email)
        
        background_tasks.add_task(send_delayed_email, scheduled_email.id, 5)
        return RedirectResponse(url="/", status_code=302)

@app.post("/cancel_reply/{scheduled_email_id}")
async def cancel_reply(
    scheduled_email_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_from_cookie)
):
    try:
        await cancel_reply_api(scheduled_email_id, db, current_user)
    except HTTPException:
        pass
    return RedirectResponse(url="/", status_code=302)

@app.get("/pending_emails")
async def get_pending_emails_api_old(
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

@app.post("/login", response_class=RedirectResponse)
def login_post(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = get_user(db, email)
    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Nieprawidłowy email lub hasło"
        })

    # Utwórz JWT
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    token = create_access_token(
        data={"sub": user.login_app},
        expires_delta=access_token_expires
    )

    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=False,  # Ustaw na True jeśli używasz HTTPS
        samesite="lax",
        max_age=int(access_token_expires.total_seconds())
    )
    return response



@app.get("/register", response_class=HTMLResponse)
def register_get(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register", response_class=HTMLResponse)
def register_post(
    request: Request,
    login_app: str = Form(...),
    password: str = Form(...),
    admin_key: str = Form(...)  # Dodaj to pole do formularza HTML
):
    # Sprawdź klucz administratora
    if admin_key != ADMIN_KEY:
        return templates.TemplateResponse(
            "register.html",
            {
                "request": request,
                "error": "Nieprawidłowy klucz administratora."
            }
        )
    
    # Reszta kodu bez zmian
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
    response.delete_cookie(
        key="access_token",  # nazwa ciasteczka z JWT
        path="/",            # ważne, musi być zgodne z tym co było przy set_cookie
    )
    return response