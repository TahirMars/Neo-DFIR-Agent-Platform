"""
取证分析智能体。
- create_forensic_agent() / run_forensic_agent(): 工厂与运行函数
- forensic_agent_node(): 图节点，供多节点图架构使用
"""
import logging
from collections.abc import Callable
from typing import Any

from langchain_core.messages import HumanMessage
from langgraph.prebuilt import create_react_agent

from src.core.config import get_settings
from src.agents.llm import get_chat_model, invoke_react_agent_with_llm_stream, message_to_text
from src.agents.prompts import FORENSIC_ANALYSIS_PROMPT
from src.agents.tool_call_utils import extract_tool_calls_from_messages
from src.agents.middleware.memory import load_case_memory
from src.agents.tools import create_evidence_analysis_tools
from src.graph.context import compose_agent_user_context
from src.skills.injector import build_skills_system_suffix

logger = logging.getLogger(__name__)

FORENSIC_RECURSION_LIMIT = 30


def create_forensic_agent(
    case_id: str,
    evidence_ids: list[str],
    session_id: str,
    log_files: list[dict[str, Any]],
    case_memory: str = "",
    skills_system_suffix: str = "",
):
    """创建取证分析 ReAct Agent（编译后的图）。"""
    tools = create_evidence_analysis_tools(case_id, evidence_ids, session_id, log_files)
    system_prompt = FORENSIC_ANALYSIS_PROMPT
    if case_memory:
        system_prompt = (
            f"<案件记忆（跨会话共享，发现重要信息时用 case_memory_update 更新）>\n{case_memory}\n</案件记忆>\n\n"
            + system_prompt
        )
    if skills_system_suffix.strip():
        system_prompt = system_prompt + "\n\n" + skills_system_suffix.strip()
    timeout = get_settings().llm_timeout_agent_seconds
    return create_react_agent(
        # 与 general_chat 一致：streaming=True 时 astream(messages) 才能逐块转发 LLM 输出
        model=get_chat_model(max_tokens=16384, timeout=timeout, streaming=True),
        tools=tools,
        prompt=system_prompt,
        name="forensic_react",
    )


def build_forensic_user_message(log_files: list[dict[str, Any]]) -> str:
    """构建取证分析的用户提示消息。"""
    file_list = "\n".join(
        f"- {f['path']} ({f.get('ext', '?')}, {round(f.get('size', 0) / 1024, 1)} KB)"
        for f in log_files[:20]
    )
    large_hint = ""
    large_files = [f for f in log_files if f.get("size", 0) > 30_000]
    if large_files:
        large_hint = (
            f"\n\n⚠️ 其中 {len(large_files)} 个文件超过 30 KB，"
            f"请优先用 evidence_read_tool(..., structured=True) 做表格/JSON 摘要，或分页 evidence_read_tool(offset/limit)，避免一次读满上下文。"
        )
    return (
        f"请分析以下取证数据中的日志文件：\n\n{file_list}{large_hint}\n\n"
        f"分析策略：\n"
        f"1. 用 evidence_ls_tool(only_classified_logs=True) 或 evidence_ls_tool + path_prefix 确认文件清单\n"
        f"2. 文本日志：evidence_read_tool 按行分页；CSV/JSON/JSONL 等用 evidence_read_tool(structured=True)\n"
        f"3. 检索用 evidence_grep_tool；模式匹配文件用 evidence_glob_tool\n"
        f"4. 提取 IOC、威胁信息、攻击时间线，输出关键发现和修复建议"
    )


async def run_forensic_agent(
    case_id: str,
    evidence_ids: list[str],
    session_id: str,
    log_files: list[dict[str, Any]],
    case_memory: str = "",
    task_description: str = "",
    token_callback: Callable[[str], None] | None = None,
    skills_system_suffix: str = "",
) -> dict[str, Any]:
    """运行取证分析 Agent 并返回结构化结果。

    Args:
        task_description: Supervisor 传递的具体任务描述。若为空，使用默认分析提示。

    Returns:
        {"status": str, "analysis": str, "files_analyzed": int, "tool_calls": list}
    """
    if not log_files:
        return {
            "status": "skipped",
            "analysis": "无日志文件",
            "files_analyzed": 0,
            "tool_calls": [],
            "streamed_via_llm": False,
        }

    agent = create_forensic_agent(
        case_id, evidence_ids, session_id, log_files, case_memory, skills_system_suffix=skills_system_suffix,
    )
    user_msg = task_description or build_forensic_user_message(log_files)

    try:
        result, streamed_via_llm = await invoke_react_agent_with_llm_stream(
            agent,
            {"messages": [HumanMessage(content=user_msg)]},
            {"recursion_limit": FORENSIC_RECURSION_LIMIT},
            token_callback,
        )
        analysis = message_to_text(result["messages"][-1]) if result.get("messages") else ""
        tool_calls = extract_tool_calls_from_messages(result.get("messages", []))
        return {
            "status": "completed",
            "analysis": analysis,
            "files_analyzed": len(log_files),
            "tool_calls": tool_calls,
            "streamed_via_llm": streamed_via_llm,
        }
    except Exception as e:
        logger.error("取证分析智能体执行失败: %s", e, exc_info=True)
        return {
            "status": "failed",
            "analysis": f"取证分析执行出错: {e}",
            "files_analyzed": 0,
            "tool_calls": [],
            "streamed_via_llm": False,
        }


async def forensic_agent_node(state: dict[str, Any]) -> dict[str, Any]:
    """图节点：执行取证分析，更新 agent_results 和 messages。"""
    from langchain_core.messages import AIMessage

    from src.agents.llm import make_stream_helpers

    writer, token_cb = make_stream_helpers(state, "forensic_agent")
    if writer:
        writer({"type": "agent_start", "agent": "forensic_agent"})

    case_id = state.get("case_id", "")
    session_id = state.get("session_id", "")
    evidence_ids = state.get("evidence_ids") or []
    # 每次从磁盘加载，避免仅首轮注入导致跨节点/多轮工具写盘后上下文仍停留在旧快照
    case_memory = load_case_memory(case_id) if case_id else ""
    classifications = state.get("file_classifications") or {}
    log_files = classifications.get("log", [])

    ctx_block = compose_agent_user_context(state).strip()
    base_task = build_forensic_user_message(log_files)
    task_description = f"{ctx_block}\n\n---\n\n{base_task}" if ctx_block else base_task

    skills_suffix = build_skills_system_suffix(
        {
            "active_skill_ids": state.get("active_skill_ids") or [],
            "case_id": case_id,
            "skills_inject_mode": state.get("skills_inject_mode") or "full",
        },
        for_agent="forensic",
    )
    result = await run_forensic_agent(
        case_id=case_id,
        evidence_ids=evidence_ids,
        session_id=session_id,
        log_files=log_files,
        case_memory=case_memory,
        task_description=task_description,
        token_callback=token_cb,
        skills_system_suffix=skills_suffix,
    )

    if writer:
        if result.get("status") == "failed":
            err_msg = result.get("analysis", "").strip() or result.get("error", "未知错误")
            writer({"type": "agent_error", "agent": "forensic_agent", "message": err_msg})
        if result.get("tool_calls"):
            writer({"type": "tool_calls", "agent": "forensic_agent", "tool_calls": result["tool_calls"]})
        if result.get("analysis") and not (token_cb and result.get("streamed_via_llm")):
            writer({"type": "token", "agent": "forensic_agent", "content": result["analysis"]})
        writer({"type": "agent_end", "agent": "forensic_agent"})

    agent_results = dict(state.get("agent_results") or {})
    agent_results["forensic"] = {
        "status": result["status"],
        "analysis": result.get("analysis", ""),
        "files_analyzed": result.get("files_analyzed", 0),
    }

    content = result.get("analysis", "取证分析未产出结果")
    return {
        "agent_results": agent_results,
        "messages": [AIMessage(content=content, name="forensic_agent")],
        "case_memory": load_case_memory(case_id) if case_id else "",
    }
