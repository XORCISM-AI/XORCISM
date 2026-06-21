"""
SQLAlchemy Base, engines, and session factories.
Replaces XORCISMModel.XORCISMEntities (Entity Framework DbContext).
"""
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker, Session
from typing import Generator
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import config


class Base(DeclarativeBase):
    pass


# One engine per database
_engines: dict = {}
_session_factories: dict = {}


def get_engine(db_name: str):
    """Get (or create) the SQLAlchemy engine for a given database."""
    if db_name not in _engines:
        url = config.DATABASES[db_name]
        _engines[db_name] = create_engine(
            url,
            # timeout = SQLite busy-timeout (seconds): wait for the lock instead of
            # failing when the runner writes concurrently with the live server (WAL).
            connect_args={"check_same_thread": False, "timeout": 15},
            echo=False,
        )
    return _engines[db_name]


def get_session(db_name: str) -> Session:
    """Return a new SQLAlchemy session for the given database."""
    if db_name not in _session_factories:
        engine = get_engine(db_name)
        _session_factories[db_name] = sessionmaker(bind=engine)
    return _session_factories[db_name]()


@contextmanager
def session_scope(db_name: str) -> Generator[Session, None, None]:
    """Context manager that provides a transactional session scope."""
    session = get_session(db_name)
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
