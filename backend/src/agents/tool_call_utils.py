"""
从 LangGraph ReAct Agent 的 messages 中提取工具调用记录。
用于 P2 工具调用详细展示。
"""
from typing import Any


def _get_tc_id(tc: Any) -> str:
    return (getattr(tc, "id", None) or (tc.get("id") if isinstance(tc, dict) else None) or "")


def _get_tc_name(tc: Any) -> str:
    return (getattr(tc, "name", None) or (tc.get("name") if isinstance(tc, dict) else None) or "unknown")


def _get_tc_args(tc: Any) -> dict:
    args_raw = getattr(tc, "args", None) or (tc.get("args") if isinstance(tc, dict) else {}) or {}
    return args_raw if isinstance(args_raw, dict) else {}


def extract_tool_calls_from_messages(messages: list) -> list[dict[str, Any]]:
    """
    从 agent.ainvoke 返回的 messages 中提取工具调用列表。
    返回 [{name, args, result, status}, ...]
    """
    tool_results: dict[str, dict[str, Any]] = {}
    order: list[str] = []

    for msg in messages:
        if hasattr(msg, "tool_calls") and msg.tool_calls:
            for tc in msg.tool_calls:
                tid = _get_tc_id(tc)
                if tid and tid not in tool_results:
                    tool_results[tid] = {
                        "name": _get_tc_name(tc),
                        "args": _get_tc_args(tc),
                        "result": None,
                        "status": "completed",
                    }
                    order.append(tid)

        if getattr(msg, "type", None) == "tool":
            tid = getattr(msg, "tool_call_id", None) or ""
            content = getattr(msg, "content", None) or ""
            if isinstance(content, list):
                content = str(content)
            if tid in tool_results:
                tool_results[tid]["result"] = content
            elif tid:
                tool_results[tid] = {
                    "name": "?",
                    "args": {},
                    "result": content,
                    "status": "completed",
                }
                order.append(tid)

    return [tool_results[tid] for tid in order if tid in tool_results]
