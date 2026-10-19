"""
Neo 应用入口：挂载 API 与生命周期。
"""
from contextlib import asynccontextmanager

from src.api.app import create_app
from src.db import init_db


@asynccontextmanager
async def lifespan(app):
    """应用生命周期：启动时建表并初始化默认用户，关闭时清理。"""
    try:
        init_db()
        from src.core import auth
        auth._init_default_users()
    except UnicodeDecodeError as e:
        raise RuntimeError(str(e)) from e
    yield
    # 关闭时清理（如 DB 连接池）


app = create_app(lifespan=lifespan)
