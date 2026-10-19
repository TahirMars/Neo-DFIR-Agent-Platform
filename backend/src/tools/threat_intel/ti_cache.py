"""
威胁情报缓存与白名单（参考 ref/mcp-server/mcp-ti/db.py）。
支持内存缓存（完整结果对象）；可选 SQLite 持久化（TI_CACHE_PATH）。
白名单从文件读取（TI_WHITELIST_PATH），每行一个 IOC。
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# 内存缓存：ioc_key -> 完整情报结果 dict
_memory_cache: dict[str, dict[str, Any]] = {}


def get_whitelist(file_path: str | None) -> set[str]:
    """从文件读取白名单，每行一个 IOC。"""
    if not file_path or not file_path.strip():
        return set()
    path = Path(file_path).resolve()
    if not path.exists() or not path.is_file():
        return set()
    out: set[str] = set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if s:
                    out.add(s)
    except Exception:
        pass
    return out


def _cache_key(ioc_type: str, value: str) -> str:
    return f"{ioc_type}:{value.strip().lower()}"


# ---------------------------------------------------------------------------
# 内存缓存
# ---------------------------------------------------------------------------

def memory_clear() -> int:
    """清空内存缓存，返回被清除的条目数。"""
    n = len(_memory_cache)
    _memory_cache.clear()
    return n


def memory_delete(ioc_type: str, value: str) -> bool:
    """删除单条内存缓存。"""
    return _memory_cache.pop(_cache_key(ioc_type, value), None) is not None


def memory_get(ioc_type: str, value: str) -> dict[str, Any] | None:
    """从内存缓存获取完整情报结果。"""
    return _memory_cache.get(_cache_key(ioc_type, value))


def memory_set(ioc_type: str, value: str, result: dict[str, Any]) -> None:
    """将完整情报结果写入内存缓存。"""
    _memory_cache[_cache_key(ioc_type, value)] = result


# ---------------------------------------------------------------------------
# SQLite 持久缓存
# ---------------------------------------------------------------------------

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS ti_cache_v2 (
    ioc_key TEXT PRIMARY KEY,
    ioc_type TEXT,
    ioc_value TEXT,
    verdict TEXT,
    confidence REAL,
    result_json TEXT,
    updated_at TEXT
)
"""


def sqlite_get(db_path: str, ioc_type: str, value: str) -> dict[str, Any] | None:
    """从 SQLite 缓存获取完整情报结果。"""
    if not db_path or not db_path.strip():
        return None
    key = _cache_key(ioc_type, value)
    try:
        conn = sqlite3.connect(db_path, timeout=5.0)
        conn.execute(_CREATE_TABLE_SQL)
        cur = conn.execute(
            "SELECT result_json FROM ti_cache_v2 WHERE ioc_key = ?", (key,),
        )
        row = cur.fetchone()
        conn.close()
        if not row or not row[0]:
            return None
        return json.loads(row[0])
    except Exception:
        return None


def sqlite_set(db_path: str, ioc_type: str, value: str, result: dict[str, Any]) -> None:
    """将完整情报结果写入 SQLite 缓存。"""
    if not db_path or not db_path.strip():
        return
    key = _cache_key(ioc_type, value)
    try:
        conn = sqlite3.connect(db_path, timeout=5.0)
        conn.execute(_CREATE_TABLE_SQL)
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """INSERT OR REPLACE INTO ti_cache_v2
               (ioc_key, ioc_type, ioc_value, verdict, confidence, result_json, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                key,
                ioc_type,
                value.strip(),
                result.get("verdict", "unknown"),
                result.get("confidence", 0.0),
                json.dumps(result, ensure_ascii=False, default=str),
                now,
            ),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def sqlite_delete(db_path: str, ioc_type: str, value: str) -> bool:
    """删除 SQLite 缓存中的单条记录。"""
    if not db_path or not db_path.strip():
        return False
    key = _cache_key(ioc_type, value)
    try:
        conn = sqlite3.connect(db_path, timeout=5.0)
        cur = conn.execute("DELETE FROM ti_cache_v2 WHERE ioc_key = ?", (key,))
        conn.commit()
        deleted = cur.rowcount > 0
        conn.close()
        return deleted
    except Exception:
        return False
