"""Database configuration file"""
import os
from contextlib import contextmanager

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

load_dotenv(override=True)
db_url = os.environ["DATABASE_URL"]
engine = create_engine(db_url)
session = sessionmaker(expire_on_commit=False, autocommit=False, autoflush=False, bind=engine)


def get_db():
    """Yield a database session and close it after the request finishes."""
    db = session()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope():
    """Open a session and guarantee it is closed (sync/background workers)."""
    db = session()
    try:
        yield db
    finally:
        db.close()
