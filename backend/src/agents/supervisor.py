"""
主管（Supervisor）节点 — 多节点图架构。

Supervisor 负责：
  1. 证据分类（首次进入时）
  2. 通过 route_after_supervisor 决定下一节点

图结构：START → supervisor → 条件路由 → forensic/sample/report/general_chat
        forensic/sample 执行后回到 supervisor，report/general_chat 到 END
"""
import logging
from typing import Any

from langgraph.graph import END

from src.agents.llm import make_stream_helpers
from src.tools.evidence.tools import classify_evidence_files, get_evidence_manifest

logger = logging.getLogger(__name__)


async def supervisor_node(state: dict[str, Any]) -> dict[str, Any]:
    """
    Supervisor 节点：证据分类 + 为路由提供状态。

    首次进入时进行证据分类，更新 file_classifications。
    从 forensic/sample 返回时仅透传状态，由 route_after_supervisor 决定下一节点。
    """
    writer, _ = make_stream_helpers(state, "supervisor")
    if writer:
        writer({"type": "agent_start", "agent": "supervisor"})

    case_id = state.get("case_id", "")
    session_id = state.get("session_id", "")
    evidence_ids = state.get("evidence_ids") or []
    file_classifications = dict(state.get("file_classifications") or {})

    # 若尚未分类，执行证据分类
    if not file_classifications and evidence_ids:
        classifications: dict[str, list] = {"binary": [], "log": [], "other": []}
        for eid in evidence_ids:
            classification = classify_evidence_files(eid)
            for cat in ("binary", "log", "other"):
                classifications[cat].extend(classification.get(cat, []))
        file_classifications = classifications

    if writer:
        writer({"type": "agent_end", "agent": "supervisor"})

    return {"file_classifications": file_classifications or {}}


def route_after_supervisor(state: dict[str, Any]):
    """
    根据 file_classifications 和 agent_results 决定下一节点。

    路由逻辑：
    - 无证据 → general_chat
    - 有日志且取证未完成 → forensic_agent
    - 有二进制且样本未完成 → sample_agent
    - 取证和样本均完成（或不需要）→ report_generator
    - 报告已完成 → END
    """
    classifications = state.get("file_classifications") or {}
    agent_results = state.get("agent_results") or {}

    log_files = classifications.get("log", [])
    binary_files = classifications.get("binary", [])

    forensic_done = "forensic" in agent_results
    sample_done = "sample" in agent_results
    report_done = "report" in agent_results

    # 无证据 → DFIR 咨询
    if not log_files and not binary_files:
        return "general_chat"

    # 有日志且取证未完成 → 取证
    if log_files and not forensic_done:
        return "forensic_agent"

    # 有二进制且样本未完成 → 样本
    if binary_files and not sample_done:
        return "sample_agent"

    # 取证和样本均完成（或不需要）且报告未完成 → 报告
    if not report_done:
        return "report_generator"

    return END
