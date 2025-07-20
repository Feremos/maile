from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from .db import Base

class Email(Base):
    __tablename__="emails"
    
    id = Column(Integer, primary_key=True, index=True)
    user_email = Column(String, index=True)
    subject = Column(String)
    content = Column(String)
    classification = Column(String)
    suggested_reply = Column(String)
    received_at = Column(DateTime, default=datetime.utcnow)