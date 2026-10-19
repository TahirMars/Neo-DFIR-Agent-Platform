"""
报告生成与读取（核心服务层）。
报告内容存于 session artifact；本模块提供按 session 读取报告、以及按格式生成/返回（md/json）。
"""
from typing import Any, Callable

from src.services.session_store import get_session


def get_report_by_session(session_id: str, artifact_get_fn: Callable[[str, str], dict[str, Any]]) -> dict[str, Any] | None:
    """
    根据 session 的 report_artifact_id 通过 artifact_get_fn(session_id, artifact_id) 取回报告数据。
    artifact_get_fn 由调用方注入（如 mcp evidence.tools.session_artifacts_get 的封装）。
    """
    sess = get_session(session_id)
    if not sess:
        return None
    aid = sess.get("report_artifact_id")
    if not aid:
        return None
    try:
        out = artifact_get_fn(session_id, aid)
        if isinstance(out, dict) and out.get("ok") and out.get("data"):
            return out["data"].get("json")
        return None
    except Exception:
        return None


def generate(
    session_id: str,
    format: str = "md",
    artifact_get_fn: Callable[[str, str], dict[str, Any]] | None = None,
) -> dict[str, Any] | str | None:
    """
    按格式生成报告内容：从会话的 report artifact 取回结构化数据，返回 md 或 json 内容。
    format 为 "md" 时返回 markdown 字符串；"json" 时返回完整 JSON 对象。
    若未传入 artifact_get_fn，则仅根据 get_session 判断是否有 report_artifact_id，有则需调用方自行取 artifact。
    """
    sess = get_session(session_id)
    if not sess:
        return None
    aid = sess.get("report_artifact_id")
    if not aid:
        return None
    if not artifact_get_fn:
        return None
    raw = get_report_by_session(session_id, artifact_get_fn)
    if not raw:
        return None
    format = (format or "md").lower()
    if format == "json":
        return raw
    if format == "md":
        return raw.get("markdown") if isinstance(raw, dict) else None
    return raw.get("markdown") if isinstance(raw, dict) else None
