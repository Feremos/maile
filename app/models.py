from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from .db import Base
from sqlalchemy import Column, Integer, String, Boolean
from sqlalchemy import create_engine
import os
from dotenv import load_dotenv
from sqlalchemy import Table
#
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(DATABASE_URL)
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    login_app = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)

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
    id = Column(Integer, primary_key=True, index=True)
    email_account_id = Column(Integer, ForeignKey("email_accounts.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    sent_from = Column(String, index=True)
    sent_to = Column(String)
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
    account = relationship("EmailAccount", back_populates="emails")
    
class EmailAccount(Base):
    __tablename__ = "email_accounts"
    id = Column(Integer, primary_key=True, index=True)
    email_address = Column(String, unique=True, nullable=False)
    provider = Column(String, nullable=False)  # 'gmail', 'imap', 'outlook'
    credentials_id = Column(Integer, ForeignKey("gmail_credentials.id"))
    active = Column(Boolean, default=True)

    credentials = relationship("GmailCredentials")
    emails = relationship("Email", back_populates="account")
    


user_email_accounts = Table(
    "user_email_accounts",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id")),
    Column("email_account_id", Integer, ForeignKey("email_accounts.id"))
)
email_accounts = relationship(
    "EmailAccount",
    secondary=user_email_accounts,
    backref="users"
)



Base.metadata.create_all(bind=engine)



