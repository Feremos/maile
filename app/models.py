from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Table, create_engine
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")
Base = declarative_base()
engine = create_engine(DATABASE_URL)

# Tabela łącząca użytkownika z wybranymi mailami (gmail_credentials)
user_selected_emails = Table(
    "user_selected_emails",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id"), primary_key=True),
    Column("gmail_credential_id", Integer, ForeignKey("gmail_credentials.id"), primary_key=True),
)

class ScheduledEmail(Base):
    __tablename__ = "scheduled_emails"
    
    id = Column(Integer, primary_key=True)
    email_id = Column(Integer, ForeignKey("emails.id"))
    reply_text = Column(String)
    scheduled_time = Column(DateTime)
    status = Column(String, default="pending")  # pending/sent/cancelled
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relacja do Email
    email = relationship("Email", back_populates="scheduled_emails")
    
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    login_app = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)

    # relacja do wybranych gmail_credentials
    selected_gmail_credentials = relationship(
        "GmailCredentials",
        secondary=user_selected_emails,
        back_populates="users_selected_by"
    )

class GmailCredentials(Base):
    __tablename__ = "gmail_credentials"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, nullable=False)
    login = Column(String, nullable=False)
    encrypted_password = Column(String, nullable=False)
    smtp_server = Column(String, nullable=False)
    smtp_port = Column(Integer, nullable=False)
    use_tls = Column(Boolean, default=True)

    users_selected_by = relationship(
        "User",
        secondary=user_selected_emails,
        back_populates="selected_gmail_credentials"
    )

class Email(Base):
    __tablename__ = "emails"
    id = Column(Integer, primary_key=True)
    sent_from = Column(String)
    sent_to = Column(String, index=True)
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

Base.metadata.create_all(bind=engine)
