"""
上下文摘要与压缩中间件。

当 session_memory 超过阈值时，将旧消息通过 LLM 摘要，完整历史卸载到文件，
保留关键取证发现（IOC、时间线、关键发现）。
"""
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from src.core.config import get_settings
from src.agents.llm import get_chat_model

logger = logging.getLogger(__name__)

# 默认触发阈值由 Settings.context_memory_trigger_chars 提供；此处作兼容回退
_FALLBACK_TRIGGER_CHARS = 60_000
DEFAULT_TRIGGER_CHARS = _FALLBACK_TRIGGER_CHARS  # 兼容 middleware.__init__ 导出
DEFAULT_KEEP_RECENT = 6  # 保留最近 N 条消息不摘要

DFIR_SUMMARY_PROMPT = """你是一位数字取证与事件响应（DFIR）分析助手。请将以下对话历史压缩为简洁摘要，必须保留：
1. 已确认的 IOC（IP、域名、哈希、URL 等）
2. 攻击时间线或关键时间点
3. 重要发现与结论
4. 待验证的假设或未解决问题
5. 用户明确要求记住的偏好

用中文输出，结构清晰，去除冗余。若无可保留内容则输出「无关键信息」。"""


def _approx_tokens(text: str) -> int:
    """粗略估算 token 数（约 4 字符/token）。"""
    return max(1, len(text) // 4)


def _serialize_memory_to_markdown(messages: list[dict[str, str]]) -> str:
    """将消息列表序列化为 Markdown。"""
    lines = []
    for m in messages:
        role = m.get("role", "user")
        content = (m.get("content") or "").strip()
        if not content:
            continue
        prefix = "**用户**" if role == "user" else "**助手**"
        lines.append(f"### {prefix}\n\n{content}\n")
    return "\n".join(lines)


async def compact_session_memory(
    session_memory: list[dict[str, str]],
    session_id: str,
    case_id: str = "",
    trigger_chars: int | None = None,
    keep_recent: int = DEFAULT_KEEP_RECENT,
) -> tuple[list[dict[str, str]], str | None]:
    """
    当 session_memory 总字符数超过阈值时，压缩旧消息。

    Args:
        trigger_chars: 为 None 时使用 ``Settings.context_memory_trigger_chars``。

    Returns:
        (compressed_memory, history_file_path or None)
        - compressed_memory: 压缩后的消息列表（摘要 + 最近 N 条）
        - history_file_path: 完整历史写入的文件路径，未压缩时为 None
    """
    if not session_memory:
        return [], None

    tc = trigger_chars
    if tc is None:
        try:
            tc = get_settings().context_memory_trigger_chars
        except Exception:
            tc = _FALLBACK_TRIGGER_CHARS

    total_chars = sum(len((m.get("content") or "")) for m in session_memory)
    if total_chars < tc:
        return session_memory, None

    # 分区：要摘要的 vs 保留的
    to_summarize = session_memory[:-keep_recent] if len(session_memory) > keep_recent else []
    to_keep = session_memory[-keep_recent:] if len(session_memory) > keep_recent else session_memory

    if not to_summarize:
        return session_memory, None

    settings = get_settings()
    if case_id:
        session_dir = settings.workspace_root_dir() / case_id / "sessions" / session_id
    else:
        session_dir = settings.session_export_dir() / session_id  # 回退
    session_dir.mkdir(parents=True, exist_ok=True)
    history_path = session_dir / "conversation_history.md"

    # 1. 将完整历史追加到文件
    try:
        section = f"\n\n---\n## {datetime.now().isoformat()}\n\n"
        section += _serialize_memory_to_markdown(to_summarize)
        with open(history_path, "a", encoding="utf-8") as f:
            f.write(section)
    except Exception as e:
        logger.warning("写入历史文件失败: %s", e)

    # 2. LLM 摘要
    try:
        from langchain_core.messages import HumanMessage, SystemMessage

        to_summarize_text = _serialize_memory_to_markdown(to_summarize)
        lc_messages = [
            SystemMessage(content=DFIR_SUMMARY_PROMPT),
            HumanMessage(content=f"请压缩以下对话历史：\n\n{to_summarize_text[:30000]}"),
        ]
        model = get_chat_model(max_tokens=2048, temperature=0.2)
        result = await model.ainvoke(lc_messages)
        summary = (result.content or "").strip() or "（摘要生成失败）"
    except Exception as e:
        logger.warning("摘要生成失败: %s，使用截断", e)
        summary = f"（早期对话摘要失败: {e}，完整历史已保存至 {history_path}）"

    # 3. 构建压缩后的 memory：摘要作为一条系统/用户消息 + 最近消息
    file_ref = f"\n\n[完整历史已保存至 workspace: conversation_history.md，可用 workspace_read 读取]"
    summary_msg = {"role": "user", "content": f"【此前对话摘要】\n{summary}{file_ref}"}
    compressed = [summary_msg] + to_keep

    return compressed, str(history_path)
