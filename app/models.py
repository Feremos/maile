from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from .db import Base
from sqlalchemy import Column, Integer, String, Boolean

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)

class Email(Base):
    __tablename__ = "emails"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    user_email = Column(String, index=True)
    subject = Column(String)
    content = Column(String)
    classification = Column(String)
    suggested_reply = Column(String)
    received_at = Column(DateTime, default=datetime.utcnow)
    mail_id = Column(String)       # ID wiadomości (np. Gmail Message-ID)
    thread_id = Column(String)     # ID wątku (np. Gmail Thread-ID)
    received_from = Column(String) # np. nazwa nadawcy (From)
    
class GmailCredential(Base):
    __tablename__ = "gmail_credentials"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    gmail_address = Column(String, nullable=False)
    encrypted_password = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")

