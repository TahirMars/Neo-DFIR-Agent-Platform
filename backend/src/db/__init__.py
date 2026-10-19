"""
数据库持久化：PostgreSQL 引擎、会话与表模型。
配置 DATABASE_URL 后，案件/会话/用户/审计等将写入数据库；未配置时使用内存。
"""
from src.db.engine import get_engine, get_session_factory, init_db, is_configured
from src.db.session import get_db_session

__all__ = [
    "get_engine",
    "get_session_factory",
    "get_db_session",
    "init_db",
    "is_configured",
]
