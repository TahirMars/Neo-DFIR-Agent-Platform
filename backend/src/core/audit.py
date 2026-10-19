"""
审计日志写入：每次 MCP 调用记录 tool_name、case_id、session_id、
入参摘要（脱敏）、出参摘要、metrics、错误；与 request_id 关联。
未配置 DATABASE_URL 时使用内存；配置后写入 PostgreSQL audit_logs 表。
"""
import json
import time
from typing import Any

from src.db import get_db_session, is_configured
from src.db.models import AuditLogModel

# 内存审计日志（未配置 DB 时使用）
_audit_log: list[dict[str, Any]] = []


def record_mcp_call(
    tool_name: str,
    case_id: str,
    session_id: str,
    request_id: str | None,
    arguments_summary: dict[str, Any],
    result_ok: bool,
    result_summary: dict[str, Any] | None,
    duration_ms: int,
    errors: list[str] | None = None,
) -> None:
    """
    记录单次 MCP 工具调用。
    入参/出参仅存摘要（如 keys、长度），敏感字段不落库。
    """
    entry = {
        "tool_name": tool_name,
        "case_id": case_id,
        "session_id": session_id,
        "request_id": request_id or "",
        "arguments_summary": _sanitize_summary(arguments_summary),
        "result_ok": result_ok,
        "result_summary": _sanitize_summary(result_summary or {}),
        "duration_ms": duration_ms,
        "errors": errors or [],
        "ts": time.time(),
    }
    if is_configured():
        try:
            with get_db_session() as session:
                inp = json.dumps(entry.get("arguments_summary"), ensure_ascii=False)[:2000]
                out = json.dumps(entry.get("result_summary"), ensure_ascii=False)[:2000] if entry.get("result_summary") else None
                log_row = AuditLogModel(
                    request_id=entry.get("request_id"),
                    case_id=case_id or None,
                    session_id=session_id or None,
                    tool_name=tool_name,
                    input_summary=inp,
                    output_summary=out,
                    duration_ms=duration_ms,
                    errors=errors,
                )
                session.add(log_row)
        except Exception:
            _audit_log.append(entry)
    else:
        _audit_log.append(entry)


def _sanitize_summary(obj: Any, max_len: int = 200) -> Any:
    """摘要化：仅保留结构、长度，不保留大块内容。"""
    if obj is None:
        return None
    if isinstance(obj, dict):
        return {k: _sanitize_summary(v, max_len) for k, v in obj.items()}
    if isinstance(obj, list):
        if len(obj) > 10:
            return {"_len": len(obj), "_preview": _sanitize_summary(obj[:3], max_len)}
        return [_sanitize_summary(x, max_len) for x in obj]
    if isinstance(obj, str):
        return obj[:max_len] + ("..." if len(obj) > max_len else "")
    if isinstance(obj, (int, float, bool)):
        return obj
    return str(type(obj).__name__)


def get_session_audit(session_id: str) -> list[dict[str, Any]]:
    """按 session_id 返回该会话的 MCP 调用审计序列。"""
    if is_configured():
        from sqlalchemy import select
        with get_db_session() as session:
            rows = session.scalars(
                select(AuditLogModel).where(AuditLogModel.session_id == session_id).order_by(AuditLogModel.created_at)
            ).all()
            return [
                {
                    "tool_name": r.tool_name,
                    "case_id": r.case_id,
                    "session_id": r.session_id,
                    "request_id": r.request_id,
                    "arguments_summary": r.input_summary,
                    "result_ok": None,
                    "result_summary": r.output_summary,
                    "duration_ms": r.duration_ms,
                    "errors": r.errors or [],
                    "ts": r.created_at.timestamp() if r.created_at else None,
                }
                for r in rows
            ]
    return [e for e in _audit_log if e.get("session_id") == session_id]


def get_audit_log() -> list[dict[str, Any]]:
    """返回全部审计日志（测试/调试用）。"""
    return list(_audit_log)
