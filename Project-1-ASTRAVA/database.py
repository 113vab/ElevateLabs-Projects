"""
database.py
Purpose: Configures the SQLite database connection using SQLAlchemy ORM.
It initializes the engine and sessionmaker to interact with the database.
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Ensure the database directory exists
DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database')
os.makedirs(DB_DIR, exist_ok=True)

DB_PATH = os.path.join(DB_DIR, 'sniffer.db')
DATABASE_URL = f"sqlite:///{DB_PATH}"

# check_same_thread is set to False to allow multi-threaded access (Flask server + Scapy sniffer thread)
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    """Dependency helper to get a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
