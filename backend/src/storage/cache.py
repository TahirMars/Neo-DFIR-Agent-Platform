"""
缓存抽象（Redis 或内存回退）。
未配置 REDIS_URL 时使用进程内字典，便于本地开发与测试。
"""
from typing import Any, Optional

from src.core.config import get_settings


class CacheBackend:
    """缓存后端接口：get/set/delete/exists。"""

    def get(self, key: str) -> Optional[str]:
        raise NotImplementedError

    def set(self, key: str, value: str, ttl_seconds: Optional[int] = None) -> None:
        raise NotImplementedError

    def delete(self, key: str) -> None:
        raise NotImplementedError

    def exists(self, key: str) -> bool:
        raise NotImplementedError


class MemoryCacheBackend(CacheBackend):
    """进程内内存缓存（无 TTL 自动过期，仅用于开发）。"""

    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    def get(self, key: str) -> Optional[str]:
        return self._store.get(key)

    def set(self, key: str, value: str, ttl_seconds: Optional[int] = None) -> None:
        self._store[key] = value

    def delete(self, key: str) -> None:
        self._store.pop(key, None)

    def exists(self, key: str) -> bool:
        return key in self._store


_backend: Optional[CacheBackend] = None


def get_cache() -> CacheBackend:
    """获取缓存后端；未配置 REDIS_URL 或未安装 redis 时使用内存。"""
    global _backend
    if _backend is not None:
        return _backend
    settings = get_settings()
    if settings.redis_url:
        try:
            from redis import Redis  # 可选依赖：pip install redis
            _client = Redis.from_url(settings.redis_url, decode_responses=True)
            _backend = _RedisSyncBackend(_client)
        except Exception:
            _backend = MemoryCacheBackend()
    else:
        _backend = MemoryCacheBackend()
    return _backend


class _RedisSyncBackend(CacheBackend):
    """Redis 同步封装（需安装 redis 包）。"""

    def __init__(self, client: Any) -> None:
        self._client = client

    def get(self, key: str) -> Optional[str]:
        v = self._client.get(key)
        return v if v is None else str(v)

    def set(self, key: str, value: str, ttl_seconds: Optional[int] = None) -> None:
        if ttl_seconds is not None:
            self._client.setex(key, ttl_seconds, value)
        else:
            self._client.set(key, value)

    def delete(self, key: str) -> None:
        self._client.delete(key)

    def exists(self, key: str) -> bool:
        return bool(self._client.exists(key))
