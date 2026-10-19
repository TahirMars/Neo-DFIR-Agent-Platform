"""
数据库引擎与会话工厂。
未配置 DATABASE_URL 时 is_configured() 为 False，各服务回退到内存存储。
"""
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from src.core.config import get_settings
from src.db.models import Base

_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def is_configured() -> bool:
    """是否已配置数据库（DATABASE_URL 非空）。"""
    url = get_settings().database_url
    return bool(url and url.strip())


def get_engine() -> Engine | None:
    """获取全局引擎；未配置时返回 None。"""
    global _engine
    if _engine is not None:
        return _engine
    url = get_settings().database_url
    if not url or not url.strip():
        return None
    try:
        _engine = create_engine(
            url.strip(),
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=10,
            echo=False,
        )
        return _engine
    except UnicodeDecodeError as e:
        raise RuntimeError(
            "数据库连接字符串编码错误（常见于 Windows 下 .env 或环境变量为 GBK）。"
            "请确保：(1) .env 文件以 UTF-8 编码保存；(2) DATABASE_URL 中的用户名、密码、数据库名仅使用 ASCII 字符（勿使用中文）。"
            "原始错误: " + str(e)
        ) from e


def get_session_factory() -> sessionmaker[Session] | None:
    """获取会话工厂；未配置时返回 None。"""
    global _session_factory
    if _session_factory is not None:
        return _session_factory
    eng = get_engine()
    if eng is None:
        return None
    _session_factory = sessionmaker(eng, autocommit=False, autoflush=False, expire_on_commit=False)
    return _session_factory


def init_db() -> bool:
    """
    创建所有表（若不存在）；仅在已配置 DATABASE_URL 时执行。
    返回是否已执行建表。
    """
    eng = get_engine()
    if eng is None:
        return False
    Base.metadata.create_all(bind=eng)
    _apply_migrations(eng)
    return True


def _apply_migrations(eng: Engine) -> None:
    """轻量级自动迁移：为已有表补充新增列。"""
    from sqlalchemy import inspect, text
    insp = inspect(eng)
    if "session_messages" in insp.get_table_names():
        cols = {c["name"] for c in insp.get_columns("session_messages")}
        if "metadata" not in cols:
            with eng.begin() as conn:
                conn.execute(text(
                    "ALTER TABLE session_messages ADD COLUMN metadata JSON"
                ))
