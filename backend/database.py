from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./db.sqlite3")

# For SQLite, disable check_same_thread
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
from backend.models import Base

def init_db():
    # Import ensures models are registered with Base metadata
    import backend.models  # noqa: F401
    Base.metadata.create_all(bind=engine)
