import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv

load_dotenv()

# Odczytaj DATABASE_URL ze zmiennych środowiskowych
DATABASE_URL = os.getenv("DATABASE_URL")

# PostgreSQL nie potrzebuje connect_args={"check_same_thread": False}
engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
    