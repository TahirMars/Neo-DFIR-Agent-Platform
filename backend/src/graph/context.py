"""
多智能体会话上下文：将 API 层会话记忆与证据摘要格式化为图状态字段，供各节点拼接用户提示。

与单 Agent 路径（AgentContext.session_memory）语义对齐。
"""
from __future__ import annotations

from typing import Any

from src.core.config import get_settings

# 无 Settings 时的回退（测试可 patch get_settings）
_FALLBACK_SESSION_CTX_MAX = 12_000
_FALLBACK_COMPOSED_MAX = 28_000


def format_session_memory_for_graph(
    session_memory: list[dict[str, str]] | None,
    *,
    max_chars: int | None = None,
) -> str:
    """将 compact 后的 session_memory 列表转为可注入模型的纯文本。"""
    if not session_memory:
        return ""
    try:
        cap = max_chars if max_chars is not None else get_settings().session_context_formatted_max_chars
    except Exception:
        cap = max_chars if max_chars is not None else _FALLBACK_SESSION_CTX_MAX
    lines: list[str] = []
    for m in session_memory:
        role = (m.get("role") or "user").lower()
        content = (m.get("content") or "").strip()
        if not content:
            continue
        label = "用户" if role == "user" else "助手"
        lines.append(f"【{label}】\n{content}")
    text = "\n\n".join(lines)
    if len(text) <= cap:
        return text
    return text[-cap:] + "\n\n（更早会话已截断以控制长度）"


def compose_agent_user_context(
    state: dict[str, Any],
    *,
    max_total_chars: int | None = None,
) -> str:
    """拼接证据摘要、本会话历史与当前用户输入，供各子 Agent 作为用户侧提示。

    字段来源：executor.initial_state 中的 context_summary、session_context、user_message。

    超长时优先保留「当前用户输入」与「证据摘要」要点，从「本会话此前对话」左侧裁掉较早内容。
    """
    try:
        cap = max_total_chars if max_total_chars is not None else get_settings().composed_user_context_max_chars
    except Exception:
        cap = _FALLBACK_COMPOSED_MAX

    ctx = (state.get("context_summary") or "").strip()
    sess_work = (state.get("session_context") or "").strip()
    um = (state.get("user_message") or "").strip()

    def _blocks(session_text: str, ctx_text: str) -> tuple[str, str, str]:
        ev = f"<证据与关联上下文>\n{ctx_text}\n</证据与关联上下文>" if ctx_text else ""
        sb = f"<本会话此前对话>\n{session_text}\n</本会话此前对话>" if session_text else ""
        ub = f"<当前用户输入>\n{um}\n</当前用户输入>" if um else ""
        return ev, sb, ub

    def _join(ev: str, sb: str, ub: str) -> str:
        return "\n\n".join([b for b in [ev, sb, ub] if b])

    ev, sb, ub = _blocks(sess_work, ctx)
    text = _join(ev, sb, ub)
    if len(text) <= cap:
        return text

    for _ in range(80):
        if len(text) <= cap:
            return text
        if not sess_work:
            break
        cut = max(500, len(sess_work) // 4)
        sess_work = f"…（前略约 {cut} 字）\n{sess_work[cut:]}"
        ev, sb, ub = _blocks(sess_work, ctx)
        text = _join(ev, sb, ub)

    if len(text) > cap and ctx:
        over = len(text) - cap + 100
        ctx_short = ctx[: max(0, len(ctx) - over)]
        if len(ctx_short) < len(ctx):
            ctx_short = ctx_short + "…"
        ev, sb, ub = _blocks(sess_work, ctx_short)
        text = _join(ev, sb, ub)

    if len(text) <= cap:
        return text

    if ub and len(ub) <= cap:
        return ub
    if ub:
        return ub[: max(100, cap - 40)] + "\n（当前输入过长已截断）"
    return text[: max(100, cap - 24)] + "\n（上下文已截断）"
