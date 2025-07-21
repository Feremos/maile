from fastapi import FastAPI, Request, Form, Depends, HTTPException, status
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from .db import SessionLocal, engine
from .models import Base, Email, User
from passlib.context import CryptContext
from jose import JWTError, jwt
import datetime
from pydantic import BaseModel, EmailStr
from fastapi.responses import RedirectResponse

class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str


SECRET_KEY = "kluczsekretny" #ZMIENIC POTEM ZEBY NIE BYLO HARDCODED
ALGORITHM = "HS256"

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: datetime.timedelta = None):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + (expires_delta or datetime.timedelta(minutes=30))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user(db, email: str):
    return db.query(User).filter(User.email == email).first()


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


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
        
@app.get("/", response_class=HTMLResponse)
def read_emails(request: Request, db:Session = Depends(get_db)):
    emails = db.query(Email).order_by(Email.received_at.desc()).all()
    return templates.TemplateResponse("index.html", {"request": request, "emails": emails})

@app.post("/webhook")
async def receive_email(
    user_email: str=Form(...),
    subject: str = Form(...),
    content: str = Form(...),
    classification: str = Form(...),
    suggested_reply: str = Form(...),
    db: Session = Depends(get_db)
):
    email = Email(
        user_email=user_email,
        subject=subject,
        content=content,
        classification=classification,
        suggested_reply=suggested_reply
    )
    db.add(email)
    db.commit()
    db.refresh(email)
    return{"status": "ok", "id":email.id}

@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = get_user(db, user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    new_user = User(email=user.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"msg": "User created"}

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
    # Tu możesz dodać sesję/cookie z tokenem JWT (do dalszej rozbudowy)
    return response

@app.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register", response_class=HTMLResponse)
def register_post(request: Request, db: Session = Depends(get_db), email: str = Form(...), password: str = Form(...)):
    db_user = get_user(db, email)
    if db_user:
        return templates.TemplateResponse("register.html", {"request": request, "error": "Email już zarejestrowany"})
    hashed_password = get_password_hash(password)
    new_user = User(email=email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return RedirectResponse(url="/login", status_code=302)