"""SQLAlchemy engine/session. Switching to PostgreSQL = change DATABASE_URL."""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.core.config import get_settings


class Base(DeclarativeBase):
    pass


_engine = None
_SessionLocal: sessionmaker | None = None


def _init() -> None:
    global _engine, _SessionLocal
    url = get_settings().database_url
    kwargs = {}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
        db_path = url.replace("sqlite:///", "", 1)
        if db_path and db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    _engine = create_engine(url, future=True, **kwargs)
    _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False, future=True)


def get_engine():
    if _engine is None:
        _init()
    return _engine


def init_db() -> None:
    from app.database import models  # noqa: F401 - registers tables

    Base.metadata.create_all(get_engine())


def reset_engine() -> None:
    """Used by tests after changing DATABASE_URL."""
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None


@contextmanager
def session_scope():
    if _SessionLocal is None:
        _init()
    session = _SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
