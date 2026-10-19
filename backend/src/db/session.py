"""
数据库会话：上下文管理器与获取会话。
"""
from contextlib import contextmanager
from typing import Generator

from sqlalchemy.orm import Session

from src.db.engine import get_session_factory


@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """
    获取数据库会话（上下文管理器）；未配置 DATABASE_URL 时不可用，调用方需先检查 is_configured()。
    """
    factory = get_session_factory()
    if factory is None:
        raise RuntimeError("数据库未配置，无法创建会话")
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
