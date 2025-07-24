# models.py
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Table, create_engine
from sqlalchemy.orm import relationship, declarative_base
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")
Base = declarative_base()
engine = create_engine(DATABASE_URL)

# Relacja User <-> EmailAccount
user_email_accounts = Table(
    "user_email_accounts",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id")),
    Column("email_account_id", Integer, ForeignKey("email_accounts.id"))
)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    login_app = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)

    email_accounts = relationship("EmailAccount", secondary=user_email_accounts, back_populates="users")
    visible_emails = relationship("UserVisibleEmail", back_populates="user", cascade="all, delete-orphan")

class GmailCredentials(Base):
    __tablename__ = "gmail_credentials"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, nullable=False)
    login = Column(String, nullable=False)
    encrypted_password = Column(String, nullable=False)
    smtp_server = Column(String, nullable=False)
    smtp_port = Column(Integer, nullable=False)
    use_tls = Column(Boolean, default=True)

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

class EmailAccount(Base):
    __tablename__ = "email_accounts"
    id = Column(Integer, primary_key=True)
    email_address = Column(String, unique=True, nullable=False)
    provider = Column(String, nullable=False)
    credentials_id = Column(Integer, ForeignKey("gmail_credentials.id"))
    active = Column(Boolean, default=True)

    credentials = relationship("GmailCredentials")
    users = relationship("User", secondary=user_email_accounts, back_populates="email_accounts")

class UserVisibleEmail(Base):
    __tablename__ = "user_visible_emails"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    email = Column(String, nullable=False)

    user = relationship("User", back_populates="visible_emails")

Base.metadata.create_all(bind=engine)
