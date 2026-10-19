"""
LangGraph 多智能体协作的状态定义。
基于 TypedDict + Annotated reducer 实现 LangGraph StateGraph 的状态管理。

多节点 Supervisor 循环架构 — 路由由 route_after_supervisor 根据
    file_classifications 和 agent_results 决定。
"""
from typing import Annotated, Any, TypedDict

from langgraph.graph import add_messages
from langchain_core.messages import BaseMessage


def _merge_dict(a: dict, b: dict) -> dict:
    """字典合并 reducer：浅合并。"""
    merged = dict(a)
    merged.update(b)
    return merged


def _replace(a: Any, b: Any) -> Any:
    """直接替换 reducer。"""
    return b


class DFIRState(TypedDict):
    """DFIR 多智能体协作全局状态。

    多节点图：supervisor 路由到 forensic/sample/report/general_chat。
    """

    messages: Annotated[list[BaseMessage], add_messages]

    # 基础上下文
    case_id: str
    session_id: str
    user_message: str
    evidence_ids: list[str]
    case_memory: str

    # 会话与证据摘要（API → executor 注入，与单 Agent 的 session_memory 对齐）
    session_context: Annotated[str, _replace]  # 由 session_memory 格式化后的文本
    context_summary: Annotated[str, _replace]  # 如 evidence_ids 关联说明

    # Neo Skills（API skill_ids → executor 预计算注入块，供子 Agent system 拼接）
    active_skill_ids: Annotated[list[str], _replace]
    skills_injection_digest: Annotated[str, _replace]  # 审计用，如 id1,id2|1200c
    skills_system_suffix: Annotated[str, _replace]  # 已格式化的 system 后缀
    skills_inject_mode: Annotated[str, _replace]  # full | catalog_only

    # 证据分类（Supervisor 填充）
    file_classifications: Annotated[dict[str, Any], _merge_dict]

    # 统一的 Agent 结果容器（替代 forensic_results + sample_results）
    # 结构: {"forensic": {"status": "completed", "analysis": "...", ...}, ...}
    agent_results: Annotated[dict[str, Any], _merge_dict]

    # 最终报告
    final_report: str

    # 控制字段
    error: str
    use_streaming: bool
