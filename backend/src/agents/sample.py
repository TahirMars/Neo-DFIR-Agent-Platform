"""
样本分析智能体。
- create_sample_agent() / run_sample_agent(): 工厂与运行函数
- sample_agent_node(): 图节点，供多节点图架构使用
"""
import logging
from collections.abc import Callable
from typing import Any

from langchain_core.messages import HumanMessage
from langgraph.prebuilt import create_react_agent

from src.core.config import get_settings
from src.agents.llm import get_chat_model, invoke_react_agent_with_llm_stream, message_to_text
from src.agents.prompts import SAMPLE_ANALYSIS_PROMPT
from src.agents.tool_call_utils import extract_tool_calls_from_messages
from src.agents.middleware.memory import load_case_memory
from src.agents.tools import create_sample_tools
from src.graph.context import compose_agent_user_context
from src.skills.injector import build_skills_system_suffix

logger = logging.getLogger(__name__)

SAMPLE_RECURSION_LIMIT = 30


def create_sample_agent(
    case_id: str,
    evidence_ids: list[str],
    session_id: str,
    binary_files: list[dict[str, Any]],
    case_memory: str = "",
    skills_system_suffix: str = "",
):
    """创建样本分析 ReAct Agent（编译后的图）。"""
    tools = create_sample_tools(case_id, evidence_ids, session_id, binary_files)
    system_prompt = SAMPLE_ANALYSIS_PROMPT
    if case_memory:
        system_prompt = (
            f"<案件记忆（跨会话共享，确认恶意样本时用 case_memory_update 更新）>\n{case_memory}\n</案件记忆>\n\n"
            + system_prompt
        )
    if skills_system_suffix.strip():
        system_prompt = system_prompt + "\n\n" + skills_system_suffix.strip()
    timeout = get_settings().llm_timeout_agent_seconds
    return create_react_agent(
        model=get_chat_model(max_tokens=8192, timeout=timeout, streaming=True),
        tools=tools,
        prompt=system_prompt,
        name="sample_react",
    )


def build_sample_user_message(binary_files: list[dict[str, Any]]) -> str:
    """构建样本分析的用户提示消息。"""
    file_list = "\n".join(
        f"- {f['path']} ({f.get('ext', '?')}, {round(f.get('size', 0) / 1024, 1)} KB)"
        for f in binary_files[:50]
    )
    return (
        f"请对以下二进制样本文件进行静态分析：\n\n{file_list}\n\n"
        f"请使用工具获取文件信息并执行分析，"
        f"识别可疑文件、提取哈希 IOC、评估风险等级。"
    )


async def run_sample_agent(
    case_id: str,
    evidence_ids: list[str],
    session_id: str,
    binary_files: list[dict[str, Any]],
    case_memory: str = "",
    task_description: str = "",
    token_callback: Callable[[str], None] | None = None,
    skills_system_suffix: str = "",
) -> dict[str, Any]:
    """运行样本分析 Agent 并返回结构化结果。

    Args:
        task_description: Supervisor 传递的具体任务描述。若为空，使用默认分析提示。

    Returns:
        {"status": str, "analysis": str, "files_analyzed": int, "tool_calls": list}
    """
    if not binary_files:
        return {
            "status": "skipped",
            "analysis": "无二进制文件",
            "files_analyzed": 0,
            "tool_calls": [],
            "streamed_via_llm": False,
        }

    agent = create_sample_agent(
        case_id, evidence_ids, session_id, binary_files, case_memory, skills_system_suffix=skills_system_suffix,
    )
    user_msg = task_description or build_sample_user_message(binary_files)

    try:
        result, streamed_via_llm = await invoke_react_agent_with_llm_stream(
            agent,
            {"messages": [HumanMessage(content=user_msg)]},
            {"recursion_limit": SAMPLE_RECURSION_LIMIT},
            token_callback,
        )
        analysis = message_to_text(result["messages"][-1]) if result.get("messages") else ""
        tool_calls = extract_tool_calls_from_messages(result.get("messages", []))
        return {
            "status": "completed",
            "analysis": analysis,
            "files_analyzed": len(binary_files),
            "tool_calls": tool_calls,
            "streamed_via_llm": streamed_via_llm,
        }
    except Exception as e:
        logger.error("样本分析智能体执行失败: %s", e, exc_info=True)
        return {
            "status": "failed",
            "analysis": f"样本分析执行出错: {e}",
            "files_analyzed": 0,
            "tool_calls": [],
            "streamed_via_llm": False,
        }


async def sample_agent_node(state: dict[str, Any]) -> dict[str, Any]:
    """图节点：执行样本分析，更新 agent_results 和 messages。"""
    from langchain_core.messages import AIMessage

    from src.agents.llm import make_stream_helpers

    writer, token_cb = make_stream_helpers(state, "sample_agent")
    if writer:
        writer({"type": "agent_start", "agent": "sample_agent"})

    case_id = state.get("case_id", "")
    session_id = state.get("session_id", "")
    evidence_ids = state.get("evidence_ids") or []
    case_memory = load_case_memory(case_id) if case_id else ""
    classifications = state.get("file_classifications") or {}
    binary_files = classifications.get("binary", [])

    ctx_block = compose_agent_user_context(state).strip()
    base_task = build_sample_user_message(binary_files)
    task_description = f"{ctx_block}\n\n---\n\n{base_task}" if ctx_block else base_task

    skills_suffix = build_skills_system_suffix(
        {
            "active_skill_ids": state.get("active_skill_ids") or [],
            "case_id": case_id,
            "skills_inject_mode": state.get("skills_inject_mode") or "full",
        },
        for_agent="sample",
    )
    result = await run_sample_agent(
        case_id=case_id,
        evidence_ids=evidence_ids,
        session_id=session_id,
        binary_files=binary_files,
        case_memory=case_memory,
        task_description=task_description,
        token_callback=token_cb,
        skills_system_suffix=skills_suffix,
    )

    if writer:
        if result.get("status") == "failed":
            err_msg = result.get("analysis", "").strip() or result.get("error", "未知错误")
            writer({"type": "agent_error", "agent": "sample_agent", "message": err_msg})
        if result.get("tool_calls"):
            writer({"type": "tool_calls", "agent": "sample_agent", "tool_calls": result["tool_calls"]})
        if result.get("analysis") and not (token_cb and result.get("streamed_via_llm")):
            writer({"type": "token", "agent": "sample_agent", "content": result["analysis"]})
        writer({"type": "agent_end", "agent": "sample_agent"})

    agent_results = dict(state.get("agent_results") or {})
    agent_results["sample"] = {
        "status": result["status"],
        "analysis": result.get("analysis", ""),
        "files_analyzed": result.get("files_analyzed", 0),
    }

    content = result.get("analysis", "样本分析未产出结果")
    return {
        "agent_results": agent_results,
        "messages": [AIMessage(content=content, name="sample_agent")],
        "case_memory": load_case_memory(case_id) if case_id else "",
    }
