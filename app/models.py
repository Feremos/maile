from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Table, Boolean, create_engine
from sqlalchemy.orm import relationship
from datetime import datetime
from .db import Base
import os
from dotenv import load_dotenv

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)

user_email_accounts = Table(
    "user_email_accounts",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id")),
    Column("email_account_id", Integer, ForeignKey("email_accounts.id"))
)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    login_app = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    
    email_accounts = relationship(
        "EmailAccount",
        secondary=user_email_accounts,
        back_populates="users"
    )

class GmailCredentials(Base):
    __tablename__ = "gmail_credentials"
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
    # Usuń email_account_id i user_id
    sent_from = Column(String, index=True)
    sent_to = Column(String, index=True)  # Dodaj indeks, bo będziemy po nim filtrować
    subject = Column(String)
    content = Column(String)
    summary = Column(String)
    classification = Column(String)
    suggested_reply = Column(String)
    received_at = Column(DateTime, default=datetime.utcnow)
    mail_id = Column(String)
    thread_id = Column(String)
    received_from = Column(String)
    is_archived = Column(Boolean, default=False)
    
class EmailAccount(Base):
    __tablename__ = "email_accounts"
    id = Column(Integer, primary_key=True, index=True)
    email_address = Column(String, unique=True, nullable=False)
    provider = Column(String, nullable=False)  # 'gmail', 'imap', 'outlook'
    credentials_id = Column(Integer, ForeignKey("gmail_credentials.id"))
    active = Column(Boolean, default=True)

    credentials = relationship("GmailCredentials")
    emails = relationship("Email", back_populates="account")

    users = relationship(
        "User",
        secondary=user_email_accounts,
        back_populates="email_accounts"
    )

Base.metadata.create_all(bind=engine)
