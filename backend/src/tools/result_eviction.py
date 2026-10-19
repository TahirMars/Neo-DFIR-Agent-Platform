"""
大结果自动卸载：工具输出超过阈值时写入文件，返回预览摘要。

参考 DeepAgents wrap_tool_call 逻辑，避免大日志解析/样本分析结果撑爆上下文窗口。
"""
import logging
from pathlib import Path
from typing import Any

from src.core.config import get_settings

logger = logging.getLogger(__name__)

# 约 4 字符/token，20K tokens ≈ 80K 字符，使用 50K 字符作为阈值（约 12.5K tokens）
EVICTION_THRESHOLD_CHARS = 50_000
PREVIEW_LINES = 30
PREVIEW_CHARS = 8000


def evict_large_result(
    result: str,
    case_id: str,
    session_id: str,
    tool_name: str,
    tool_call_id: str | None = None,
) -> str:
    """
    若结果超过阈值，写入文件并返回预览。
    路径: workspace/{case_id}/sessions/{session_id}/tool_results/

    Args:
        result: 工具返回的完整字符串
        case_id: 案件 ID
        session_id: 会话 ID
        tool_name: 工具名称（用于文件名）
        tool_call_id: 可选，用于唯一文件名

    Returns:
        原结果或预览字符串
    """
    if not result or len(result) < EVICTION_THRESHOLD_CHARS:
        return result

    settings = get_settings()
    workspace_root = settings.workspace_root_dir()
    cid = (case_id or "").strip() or "_unknown"
    tool_results_dir = workspace_root / cid / "sessions" / session_id / "tool_results"
    tool_results_dir.mkdir(parents=True, exist_ok=True)

    suffix = f"_{tool_call_id}" if tool_call_id else ""
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in tool_name)
    filename = f"{safe_name}{suffix}.txt"
    filepath = tool_results_dir / filename

    try:
        filepath.write_text(result, encoding="utf-8")
    except Exception as e:
        logger.warning("写入工具结果文件失败: %s", e)
        return result[:PREVIEW_CHARS] + "\n\n... (输出过长，截断显示)"

    lines = result.splitlines()
    preview = "\n".join(lines[:PREVIEW_LINES])
    if len(preview) > PREVIEW_CHARS:
        preview = preview[:PREVIEW_CHARS] + "\n... (预览已截断)"

    total_lines = len(lines)
    total_chars = len(result)
    ref_path = f"tool_results/{filename}"

    return (
        f"[输出过大已卸载] 共 {total_lines} 行 / {total_chars} 字符。\n"
        f"预览（前 {min(PREVIEW_LINES, total_lines)} 行）：\n\n{preview}\n\n"
        f"完整结果已保存至 workspace: {ref_path}，可用 workspace_read 读取。"
    )


def evict_large_result_from_dict(
    data: dict[str, Any],
    case_id: str,
    session_id: str,
    tool_name: str,
    tool_call_id: str | None = None,
) -> str:
    """将 dict 序列化为 JSON 字符串后执行卸载。用于返回结构化数据的工具。"""
    import json
    result = json.dumps(data, ensure_ascii=False, indent=2)
    return evict_large_result(result, case_id, session_id, tool_name, tool_call_id)
