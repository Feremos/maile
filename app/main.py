from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from .db import SessionLocal, engine
from .models import Base, Email

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
    return templates.TemplateResponse("index.html", {"request": request, "email:":emails})

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