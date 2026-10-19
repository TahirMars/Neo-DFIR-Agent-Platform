"""
通用对话智能体（DFIR 咨询）。
- run_chat_agent(): 运行函数
- general_chat_node(): 图节点，供多节点图架构使用
"""
import logging
from collections.abc import Callable
from typing import Any

from langchain_core.messages import HumanMessage
from langgraph.prebuilt import create_react_agent

from src.agents.llm import get_chat_model, invoke_react_agent_with_llm_stream, message_to_text
from src.agents.prompts import DEFAULT_CHAT_PROMPT
from src.agents.tool_call_utils import extract_tool_calls_from_messages
from src.agents.tools import create_chat_tools
from src.graph.context import compose_agent_user_context
from src.skills.injector import build_skills_system_suffix

logger = logging.getLogger(__name__)


def create_chat_agent(
    case_id: str = "",
    session_id: str = "",
    skills_system_suffix: str = "",
):
    """创建通用对话 ReAct Agent。"""
    tools = create_chat_tools(case_id=case_id, session_id=session_id)
    prompt = DEFAULT_CHAT_PROMPT
    if skills_system_suffix.strip():
        prompt = prompt + "\n\n" + skills_system_suffix.strip()
    return create_react_agent(
        model=get_chat_model(max_tokens=16384, streaming=True),
        tools=tools,
        prompt=prompt,
        name="chat_react",
    )


async def run_chat_agent(
    user_message: str,
    case_id: str = "",
    session_id: str = "",
    writer: Any = None,
    token_callback: Callable[[str], None] | None = None,
    skills_system_suffix: str = "",
) -> dict[str, Any]:
    """运行通用对话 Agent。

    Returns:
        {"status": str, "reply": str, "tool_calls": list}
    """
    agent = create_chat_agent(case_id, session_id, skills_system_suffix=skills_system_suffix)
    try:
        result, streamed_via_llm = await invoke_react_agent_with_llm_stream(
            agent,
            {"messages": [HumanMessage(content=user_message)]},
            {"recursion_limit": 15},
            token_callback,
        )
        reply = message_to_text(result["messages"][-1]) if result.get("messages") else ""
        tool_calls = extract_tool_calls_from_messages(result.get("messages", []))
        return {
            "status": "completed",
            "reply": reply,
            "tool_calls": tool_calls,
            "streamed_via_llm": streamed_via_llm,
        }
    except Exception as e:
        logger.error("通用对话智能体执行失败: %s", e, exc_info=True)
        return {
            "status": "failed",
            "reply": f"对话处理出错: {e}",
            "tool_calls": [],
            "streamed_via_llm": False,
        }


async def general_chat_node(state: dict[str, Any]) -> dict[str, Any]:
    """图节点：执行 DFIR 咨询，更新 agent_results 和 messages。"""
    from langchain_core.messages import AIMessage

    from src.agents.llm import make_stream_helpers

    writer, token_cb = make_stream_helpers(state, "general_chat")
    if writer:
        writer({"type": "agent_start", "agent": "general_chat"})

    case_id = state.get("case_id", "")
    session_id = state.get("session_id", "")
    user_message = compose_agent_user_context(state) or (state.get("user_message") or "")

    skills_suffix = build_skills_system_suffix(
        {
            "active_skill_ids": state.get("active_skill_ids") or [],
            "case_id": case_id,
            "skills_inject_mode": state.get("skills_inject_mode") or "full",
        },
        for_agent="general_chat",
    )
    result = await run_chat_agent(
        user_message=user_message,
        case_id=case_id,
        session_id=session_id,
        token_callback=token_cb,
        skills_system_suffix=skills_suffix,
    )

    if writer:
        if result.get("status") == "failed":
            err_msg = result.get("reply", "").strip() or result.get("error", "未知错误")
            writer({"type": "agent_error", "agent": "general_chat", "message": err_msg})
        if result.get("tool_calls"):
            writer({"type": "tool_calls", "agent": "general_chat", "tool_calls": result["tool_calls"]})
        if result.get("reply") and not (token_cb and result.get("streamed_via_llm")):
            writer({"type": "token", "agent": "general_chat", "content": result["reply"]})
        writer({"type": "agent_end", "agent": "general_chat"})

    agent_results = dict(state.get("agent_results") or {})
    agent_results["general_chat"] = {
        "status": result["status"],
        "analysis": result.get("reply", ""),
    }

    content = result.get("reply", "DFIR 咨询未产出结果")
    return {
        "agent_results": agent_results,
        "messages": [AIMessage(content=content, name="general_chat")],
        "final_report": content,
    }
