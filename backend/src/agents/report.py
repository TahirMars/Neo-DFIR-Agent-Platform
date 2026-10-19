"""
报告生成智能体。
- create_report_agent() / run_report_agent(): 工厂与运行函数
- report_node(): 图节点，供多节点图架构使用
"""
import logging
from collections.abc import Callable
from typing import Any

from langchain_core.messages import HumanMessage
from langgraph.prebuilt import create_react_agent

from src.agents.llm import get_chat_model, invoke_react_agent_with_llm_stream, message_to_text
from src.agents.prompts import REPORT_GENERATION_PROMPT
from src.agents.tool_call_utils import extract_tool_calls_from_messages
from src.agents.middleware.memory import load_case_memory
from src.agents.tools import create_report_tools
from src.graph.context import compose_agent_user_context
from src.skills.injector import build_skills_system_suffix

logger = logging.getLogger(__name__)

REPORT_RECURSION_LIMIT = 15


def create_report_agent(
    case_id: str,
    evidence_ids: list[str],
    session_id: str,
    case_memory: str = "",
    skills_system_suffix: str = "",
):
    """创建报告生成 ReAct Agent（编译后的图）。"""
    tools = create_report_tools(case_id, evidence_ids, session_id)
    system_prompt = REPORT_GENERATION_PROMPT
    if case_memory:
        system_prompt = (
            f"<案件记忆（跨会话共享）>\n{case_memory}\n</案件记忆>\n\n"
            + system_prompt
        )
    if skills_system_suffix.strip():
        system_prompt = system_prompt + "\n\n" + skills_system_suffix.strip()
    return create_react_agent(
        model=get_chat_model(max_tokens=16384, streaming=True),
        tools=tools,
        prompt=system_prompt,
        name="report_react",
    )


async def run_report_agent(
    case_id: str,
    evidence_ids: list[str],
    session_id: str,
    analysis_summary: str,
    user_message: str = "",
    case_memory: str = "",
    token_callback: Callable[[str], None] | None = None,
    skills_system_suffix: str = "",
) -> dict[str, Any]:
    """运行报告生成 Agent 并返回结构化结果。

    Args:
        analysis_summary: Supervisor 整理的各子 Agent 分析结果摘要。

    Returns:
        {"status": str, "report": str, "tool_calls": list}
    """
    agent = create_report_agent(
        case_id, evidence_ids, session_id, case_memory, skills_system_suffix=skills_system_suffix,
    )

    if analysis_summary.strip():
        user_prompt = (
            f"## 用户原始问题\n{user_message}\n\n"
            f"## 子智能体分析结果\n"
            f"以下是各子智能体返回的分析结果，请按系统提示中的报告模板整合输出；"
            f"若需先调工具，工具返回前勿写报告标题与正文；定稿时「# 调查溯源报告」仅出现一次。\n\n"
            f"{analysis_summary}\n\n"
            f"## 报告生成要求\n"
            f"1. 严格按照报告模板的章节结构输出\n"
            f"2. 攻击链分析必须包含 Mermaid 攻击路径图\n"
            f"3. IOC 汇总使用表格格式，分文件IOC和网络IOC\n"
            f"4. 所有结论必须标注证据来源，不要编造缺乏证据的结论\n"
            f"5. 如果某类分析缺失，在报告中注明并建议补充"
        )
    else:
        user_prompt = (
            f"## 用户问题\n{user_message}\n\n"
            f"当前没有证据分析结果。请基于用户描述的安全事件场景，按事件响应指南格式输出建议。"
        )

    try:
        result, streamed_via_llm = await invoke_react_agent_with_llm_stream(
            agent,
            {"messages": [HumanMessage(content=user_prompt)]},
            {"recursion_limit": REPORT_RECURSION_LIMIT},
            token_callback,
        )
        report = message_to_text(result["messages"][-1]) if result.get("messages") else ""
        tool_calls = extract_tool_calls_from_messages(result.get("messages", []))
        return {
            "status": "completed",
            "report": report,
            "tool_calls": tool_calls,
            "streamed_via_llm": streamed_via_llm,
        }
    except Exception as e:
        logger.error("报告生成智能体执行失败: %s", e, exc_info=True)
        return {
            "status": "failed",
            "report": f"报告生成出错: {e}",
            "tool_calls": [],
            "streamed_via_llm": False,
        }


async def report_node(state: dict[str, Any]) -> dict[str, Any]:
    """图节点：执行报告生成，更新 agent_results、final_report 和 messages。"""
    from langchain_core.messages import AIMessage

    from src.agents.llm import make_stream_helpers

    writer, token_cb = make_stream_helpers(state, "report_generator")
    if writer:
        writer({"type": "agent_start", "agent": "report_generator"})

    case_id = state.get("case_id", "")
    session_id = state.get("session_id", "")
    evidence_ids = state.get("evidence_ids") or []
    case_memory = load_case_memory(case_id) if case_id else ""
    user_message = compose_agent_user_context(state) or (state.get("user_message") or "")
    agent_results = state.get("agent_results") or {}

    # 从 agent_results 构建 analysis_summary
    parts = []
    if agent_results.get("forensic", {}).get("analysis"):
        parts.append(f"## 取证分析\n{agent_results['forensic']['analysis']}")
    if agent_results.get("sample", {}).get("analysis"):
        parts.append(f"## 样本分析\n{agent_results['sample']['analysis']}")
    analysis_summary = "\n\n".join(parts) if parts else ""

    skills_suffix = build_skills_system_suffix(
        {
            "active_skill_ids": state.get("active_skill_ids") or [],
            "case_id": case_id,
            "skills_inject_mode": state.get("skills_inject_mode") or "full",
        },
        for_agent="report",
    )
    result = await run_report_agent(
        case_id=case_id,
        evidence_ids=evidence_ids,
        session_id=session_id,
        analysis_summary=analysis_summary,
        user_message=user_message,
        case_memory=case_memory,
        token_callback=token_cb,
        skills_system_suffix=skills_suffix,
    )

    if writer:
        if result.get("tool_calls"):
            writer({"type": "tool_calls", "agent": "report_generator", "tool_calls": result["tool_calls"]})
        if result.get("report") and not (token_cb and result.get("streamed_via_llm")):
            writer({"type": "token", "agent": "report_generator", "content": result["report"]})
        writer({"type": "agent_end", "agent": "report_generator"})

    new_agent_results = dict(agent_results)
    new_agent_results["report"] = {
        "status": result["status"],
        "report": result.get("report", ""),
    }

    report_content = result.get("report", "报告生成未产出结果")
    return {
        "agent_results": new_agent_results,
        "final_report": report_content,
        "messages": [AIMessage(content=report_content, name="report_generator")],
        "case_memory": load_case_memory(case_id) if case_id else "",
    }
