import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# 1. Define the SQLite database file path inside the backend folder
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SQLALCHEMY_DATABASE_URL = f"sqlite:///{os.path.join(BASE_DIR, 'my_scanner.db')}"

# 2. Create the SQLAlchemy engine (connect_args is required for SQLite thread safety)
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

# 3. Create a SessionLocal class for database sessions per request
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 4. Base class for ORM models in models.py
Base = declarative_base()