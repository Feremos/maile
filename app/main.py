from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from .db import SessionLocal, engine
from .models import Base, Email
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from .models import User
import datetime
from fastapi import HTTPException, status

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
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

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
def register(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = get_user(db, form_data.username)
    if user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(form_data.password)
    new_user = User(email=form_data.username, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"msg": "User created"}

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = get_user(db, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}