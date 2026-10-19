"""
会话工作区落盘（P1）：分析轮次可追溯、关键子智能体产出与证据 ID 写入 artifacts；
摘要阈值前的全量对话轻量快照；含本轮助手回复的最新记忆快照。

路径：workspace/{case_id}/sessions/{session_id}/snapshots/ 与 artifacts/
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.core.config import get_settings

logger = logging.getLogger(__name__)


def _workspace_session_dir(case_id: str, session_id: str) -> Path:
    cid = (case_id or "").strip() or "_unknown"
    sid = (session_id or "").strip() or "_unknown"
    d = get_settings().workspace_root_dir() / cid / "sessions" / sid
    d.mkdir(parents=True, exist_ok=True)
    return d


def _snapshots_dir(case_id: str, session_id: str) -> Path:
    d = _workspace_session_dir(case_id, session_id) / "snapshots"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _artifacts_dir(case_id: str, session_id: str) -> Path:
    d = _workspace_session_dir(case_id, session_id) / "artifacts"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _serialize_memory_markdown(messages: list[dict[str, str]]) -> str:
    lines: list[str] = []
    for m in messages:
        role = (m.get("role") or "user").lower()
        content = (m.get("content") or "").strip()
        if not content:
            continue
        label = "用户" if role == "user" else "助手"
        lines.append(f"### {label}\n\n{content}\n")
    return "\n".join(lines)


def maybe_persist_light_pre_summarize_archive(
    case_id: str,
    session_id: str,
    session_memory: list[dict[str, str]],
) -> None:
    """当总会话字符数处于 [light, trigger) 时，覆盖写入全量对话 Markdown（不调用 LLM）。

    便于在触发 LLM 摘要前从磁盘恢复完整上下文。
    """
    if not get_settings().session_workspace_persistence_enabled:
        return
    total = sum(len((m.get("content") or "")) for m in session_memory)
    light = get_settings().context_memory_light_append_chars
    trigger = get_settings().context_memory_trigger_chars
    if not (light <= total < trigger):
        return
    path = _snapshots_dir(case_id, session_id) / "dialog_pre_summarize.md"
    try:
        body = _serialize_memory_markdown(session_memory)
        text = (
            f"# 会话全量对话快照（未达 LLM 摘要阈值）\n\n"
            f"> 当前阈值：触发摘要需约 **{trigger}** 字符；本快照在 **{light}** 字符以上生成。\n"
            f"> UTC: {datetime.now(timezone.utc).isoformat()}\n\n"
            f"{body}"
        )
        path.write_text(text, encoding="utf-8")
    except OSError as e:
        logger.warning("写入 dialog_pre_summarize.md 失败: %s", e)


def write_session_memory_latest_snapshot(
    case_id: str,
    session_id: str,
    *,
    session_memory: list[dict[str, str]],
    latest_assistant_text: str,
    context_summary: str,
) -> None:
    """覆盖写入「当前纳入模型的会话记忆 + 本轮助手回复」快照。"""
    if not get_settings().session_workspace_persistence_enabled:
        return
    mem_max = get_settings().session_memory_single_msg_max_chars
    merged = list(session_memory)
    if (latest_assistant_text or "").strip():
        merged.append({"role": "assistant", "content": latest_assistant_text.strip()[:mem_max]})
    path = _snapshots_dir(case_id, session_id) / "session_memory_latest.md"
    try:
        body = _serialize_memory_markdown(merged)
        ctx = (context_summary or "").strip() or "（无）"
        text = (
            f"# 会话记忆快照（含本轮助手回复）\n\n"
            f"> UTC: {datetime.now(timezone.utc).isoformat()}\n\n"
            f"## 证据与上下文摘要\n\n{ctx}\n\n## 对话\n\n{body}"
        )
        path.write_text(text, encoding="utf-8")
    except OSError as e:
        logger.warning("写入 session_memory_latest.md 失败: %s", e)


def _format_agent_results_markdown(agent_results: dict[str, Any], max_each: int) -> str:
    parts: list[str] = []
    for key in ("forensic", "sample", "report", "general_chat"):
        if key not in agent_results:
            continue
        block = agent_results[key]
        if not isinstance(block, dict):
            continue
        status = block.get("status", "")
        if key == "report":
            text = block.get("report") or block.get("analysis") or ""
        else:
            text = block.get("analysis") or block.get("report") or ""
        text = str(text or "")
        if len(text) > max_each:
            text = text[: max_each - 30] + "\n…（已截断，完整内容见会话消息或 tool_results）"
        parts.append(f"#### {key}\n\n- **status**: {status}\n\n{text}\n")
    return "\n".join(parts) if parts else "_（无子智能体结构化结果）_\n"


def append_analysis_run_artifact(
    case_id: str,
    session_id: str,
    *,
    user_message: str,
    evidence_ids: list[str],
    result: dict[str, Any],
    use_langgraph: bool,
    error: str | None = None,
) -> None:
    """追加本轮分析记录：用户输入、证据 ID、最终回复、各子 Agent 关键产出。"""
    if not get_settings().session_workspace_persistence_enabled:
        return
    cap = get_settings().session_run_artifact_max_chars_per_block
    explanation = (result.get("explanation") or "").strip()
    final_report = (result.get("final_report") or "").strip()
    ev_line = ", ".join(evidence_ids) if evidence_ids else "无"

    lines: list[str] = [
        "---",
        f"## {datetime.now(timezone.utc).isoformat()}",
        f"- **模式**: {'LangGraph 多智能体' if use_langgraph else '单 Agent'}",
        f"- **关联证据 evidence_ids**: {ev_line}",
    ]
    skill_ids = result.get("active_skill_ids") or []
    if skill_ids:
        lines.append(f"- **active_skill_ids**: {', '.join(str(x) for x in skill_ids)}")
    sk_digest = (result.get("skills_injection_digest") or "").strip()
    if sk_digest:
        lines.append(f"- **skills_injection_digest**: {sk_digest}")
    if error:
        lines.append(f"- **执行异常**: {error[:2000]}{'…' if len(error) > 2000 else ''}")
    lines.extend(["", "### 用户输入", "", user_message[:cap] + ("…" if len(user_message) > cap else ""), ""])

    main_out = explanation or final_report
    lines.extend(["### 最终回复（explanation / 主展示）", "", main_out[:cap] + ("…" if len(main_out) > cap else ""), ""])
    if final_report and final_report != main_out[: min(len(main_out), len(final_report))]:
        lines.extend(["### final_report", "", final_report[:cap] + ("…" if len(final_report) > cap else ""), ""])

    lines.extend(["### 子智能体结构化结果", "", _format_agent_results_markdown(result.get("agent_results") or {}, cap)])

    path = _artifacts_dir(case_id, session_id) / "analysis_runs.md"
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except OSError as e:
        logger.warning("追加 analysis_runs.md 失败: %s", e)


def persist_chat_turn_workspace(
    case_id: str,
    session_id: str,
    *,
    session_memory_before_run: list[dict[str, str]],
    context_summary: str,
    user_message: str,
    evidence_ids: list[str],
    assistant_content: str,
    result: dict[str, Any],
    use_langgraph: bool,
    error: str | None = None,
) -> None:
    """每轮对话结束后调用：轻量归档（条件）→ 最新快照 → 分析轮次追加。"""
    maybe_persist_light_pre_summarize_archive(case_id, session_id, session_memory_before_run)
    write_session_memory_latest_snapshot(
        case_id,
        session_id,
        session_memory=session_memory_before_run,
        latest_assistant_text=assistant_content,
        context_summary=context_summary,
    )
    append_analysis_run_artifact(
        case_id,
        session_id,
        user_message=user_message,
        evidence_ids=evidence_ids,
        result=result,
        use_langgraph=use_langgraph,
        error=error,
    )
