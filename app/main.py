import os
from fastapi import FastAPI, Request, Form, Depends, HTTPException, status, Query, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from .db import SessionLocal, engine
from .models import Base, Email, User, GmailCredential
from passlib.context import CryptContext
from jose import JWTError, jwt
import datetime
from pydantic import BaseModel, EmailStr
from cryptography.fernet import Fernet
from dotenv import load_dotenv
import os
import smtplib
from email.message import EmailMessage

# --- Konfiguracje ---s

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY not set in environment variables")

FERNET_KEY = os.getenv("FERNET_KEY")
if not FERNET_KEY:
    raise RuntimeError("FERNET_KEY not set in environment variables")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
fernet = Fernet(FERNET_KEY.encode())

# --- Modele Pydantic ---

class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

# --- Funkcje pomocnicze ---

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: datetime.timedelta = None):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + (expires_delta or datetime.timedelta(minutes=30))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")

def get_user(db, email: str):
    return db.query(User).filter(User.email == email).first()

def encrypt_password(password: str) -> str:
    return fernet.encrypt(password.encode()).decode()

def decrypt_password(token: str) -> str:
    return fernet.decrypt(token.encode()).decode()

# --- FastAPI setup ---

Base.metadata.create_all(bind=engine)
app = FastAPI()
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user_from_cookie(db: Session = Depends(get_db), user_email: str = Cookie(None)):
    if not user_email:
        raise HTTPException(status_code=401, detail="Nie jesteś zalogowany")
    user = get_user(db, user_email)
    if not user:
        raise HTTPException(status_code=401, detail="Nieprawidłowy użytkownik")
    return user

# --- Endpointy ---

@app.on_event("startup")
def create_predefined_users():
    db = SessionLocal()
    users_env = os.getenv("USERS")
    if not users_env:
        print("No predefined users found in USERS env variable.")
        return

    try:
        user_entries = [entry.strip() for entry in users_env.split(",") if entry.strip()]
        for entry in user_entries:
            try:
                email, password = entry.split(":")
            except ValueError:
                print(f"Skipping invalid entry: {entry}")
                continue
            if not get_user(db, email):
                hashed_pw = get_password_hash(password)
                user = User(email=email, hashed_password=hashed_pw)
                db.add(user)
        db.commit()
        print(f"Created or verified {len(user_entries)} predefined users.")
    finally:
        db.close()

@app.get("/", response_class=HTMLResponse)
def read_emails(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user_from_cookie)):
    emails = db.query(Email).order_by(Email.received_at.desc()).all()
    return templates.TemplateResponse("index.html", {"request": request, "emails": emails, "user": current_user})

@app.post("/webhook")
async def receive_email(
    user_email: str = Form(...),
    subject: str = Form(...),
    content: str = Form(...),
    classification: str = Form(...),
    suggested_reply: str = Form(...),
    mail_id: str = Form(None),
    thread_id: str = Form(None),
    received_from: str = Form(None),
    db: Session = Depends(get_db),
):
    email = Email(
        user_email=user_email,
        subject=subject,
        content=content,
        classification=classification,
        suggested_reply=suggested_reply,
        mail_id=mail_id,
        thread_id=thread_id,
        received_from=received_from
    )
    db.add(email)
    db.commit()
    db.refresh(email)
    return {"status": "ok", "id": email.id}


@app.post("/token")
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = get_user(db, user.email)
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token = create_access_token(data={"sub": db_user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login", response_class=HTMLResponse)
def login_post(request: Request, db: Session = Depends(get_db), email: str = Form(...), password: str = Form(...)):
    user = get_user(db, email)
    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Nieprawidłowy email lub hasło"})
    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(key="user_email", value=user.email, httponly=True)
    return response

@app.get("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("user_email")
    return response

@app.post("/reply")
def send_reply(
    request: Request,
    email_id: int = Form(...),
    reply_text: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_from_cookie),
):
    email = db.query(Email).filter(Email.id == email_id).first()
    if not email:
        raise HTTPException(status_code=404, detail="Email nie znaleziony")

    # Wyślij e-mail
    try:
        msg = EmailMessage()
        msg["Subject"] = f"Odpowiedź: {email.subject}"
        msg["From"] = os.getenv("SMTP_FROM_EMAIL")
        msg["To"] = email.user_email
        msg.set_content(reply_text)

        with smtplib.SMTP(os.getenv("SMTP_SERVER"), int(os.getenv("SMTP_PORT"))) as server:
            if os.getenv("SMTP_USE_TLS") == "true":
                server.starttls()
            server.login(os.getenv("SMTP_USERNAME"), os.getenv("SMTP_PASSWORD"))
            server.send_message(msg)
    except Exception as e:
        return templates.TemplateResponse("index.html", {
            "request": request,
            "emails": db.query(Email).order_by(Email.received_at.desc()).all(),
            "user": current_user,
            "error": f"Błąd podczas wysyłania maila: {e}"
        })

    return RedirectResponse(url="/", status_code=302)