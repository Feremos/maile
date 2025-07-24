import os
import re
import datetime
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Form, Depends, HTTPException, status, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from passlib.context import CryptContext
from cryptography.fernet import Fernet
from pydantic import BaseModel, EmailStr

from .db import SessionLocal, engine
from .models import Base, User, Email, GmailCredentials, EmailAccount, UserVisibleEmail

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

def get_password_hash(password): return pwd_context.hash(password)
def verify_password(plain, hashed): return pwd_context.verify(plain, hashed)
def encrypt_password(password): return fernet.encrypt(password.encode()).decode()
def decrypt_password(token): return fernet.decrypt(token.encode()).decode()

def create_access_token(data: dict, expires_delta: datetime.timedelta = None):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + (expires_delta or datetime.timedelta(minutes=30))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")

def get_user(db, email: str):
    return db.query(User).filter(User.login_app == email).first()

def get_emails_for_user(db: Session, user: User):
    visible_addresses = [v.email_address for v in user.visible_emails]
    if not visible_addresses:
        return []
    return (
        db.query(Email)
        .filter(
            Email.sent_to.in_(visible_addresses),
            Email.is_archived == False
        )
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

def extract_email(full: str):
    match = re.search(r'<([^>]+)>', full)
    return match.group(1) if match else full.strip()

@app.on_event("startup")
def create_predefined_users():
    db = SessionLocal()
    users_env = os.getenv("USERS")
    if not users_env:
        return
    try:
        for entry in users_env.split(","):
            try:
                email, password = entry.strip().split(":")
                if not get_user(db, email):
                    user = User(login_app=email, hashed_password=get_password_hash(password))
                    db.add(user)
            except ValueError:
                continue
        db.commit()
    finally:
        db.close()

@app.get("/", response_class=HTMLResponse)
def read_emails(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user_from_cookie)):
    emails = get_emails_for_user(db, current_user)
    return templates.TemplateResponse("index.html", {"request": request, "emails": emails, "user": current_user})

@app.post("/add_visible_email", response_class=HTMLResponse)
def add_visible_email(
    request: Request,
    email_address: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_from_cookie),
):
    email_address = email_address.strip().lower()
    exists = db.query(UserVisibleEmail).filter_by(user_id=current_user.id, email_address=email_address).first()
    if exists:
        return templates.TemplateResponse("index.html", {
            "request": request,
            "emails": get_emails_for_user(db, current_user),
            "user": current_user,
            "add_email_error": f"Adres {email_address} jest już na Twojej liście widocznych."
        })
    visible = UserVisibleEmail(user_id=current_user.id, email_address=email_address)
    db.add(visible)
    db.commit()
    return templates.TemplateResponse("index.html", {
        "request": request,
        "emails": get_emails_for_user(db, current_user),
        "user": current_user,
        "add_email_message": f"Adres {email_address} został dodany do widocznych."
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
def send_reply(email_id: int = Form(...), reply_text: str = Form(...), db: Session = Depends(get_db), current_user: User = Depends(get_current_user_from_cookie)):
    email = db.query(Email).filter(Email.id == email_id).first()
    if not email:
        raise HTTPException(status_code=404, detail="Email nie znaleziony")
    sent_to_clean = email.sent_to.strip().lower()
    credentials = db.query(GmailCredentials).filter(GmailCredentials.login.ilike(sent_to_clean)).first()
    if not credentials:
        raise HTTPException(status_code=500, detail="Brak danych SMTP dla tego konta")
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
    email.is_archived = True
    db.commit()
    return RedirectResponse(url="/", status_code=302)

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

@app.get("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("user_email")
    return response