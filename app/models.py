from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from .db import Base
from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy import create_engine
import os
from dotenv import load_dotenv

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)

class MailCredentials(Base):
    __tablename__ = "mail_credentials"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, nullable=False)
    login = Column(String, nullable=False)
    encrypted_password = Column(String, nullable=False)
    smtp_server = Column(String, nullable=False)
    smtp_port = Column(Integer, nullable=False)
    use_tls = Column(Boolean, default=True)
    
class Email(Base):
    __tablename__ = "emails"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    user_email = Column(String, index=True)
    subject = Column(String)
    content = Column(String)
    summary = Column(String)
    classification = Column(String)
    suggested_reply = Column(String)
    received_at = Column(DateTime, default=datetime.utcnow)
    mail_id = Column(String)       # ID wiadomości (np. Gmail Message-ID)
    thread_id = Column(String)     # ID wątku (np. Gmail Thread-ID)
    received_from = Column(String) # np. nazwa nadawcy (From)
    is_archived = Column(Boolean, default=False)
    
    
Base.metadata.create_all(bind=engine)



