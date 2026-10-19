"""
工具统一响应 Envelope 格式。
"""
from typing import Any


def envelope_ok(data: dict[str, Any], duration_ms: int = 0) -> dict[str, Any]:
    """构造成功响应 envelope。"""
    return {
        "ok": True,
        "data": data,
        "duration_ms": duration_ms,
    }


def envelope_err(errors: list[str], duration_ms: int = 0) -> dict[str, Any]:
    """构造失败响应 envelope。"""
    return {
        "ok": False,
        "errors": errors,
        "duration_ms": duration_ms,
    }
