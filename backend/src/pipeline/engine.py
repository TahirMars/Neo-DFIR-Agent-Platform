"""
流水线执行引擎：根据 pipeline 模板驱动多智能体图执行。
"""
import logging
from typing import Any

from src.agents.middleware.session_persistence import persist_chat_turn_workspace
from src.agents.middleware.summarization import compact_session_memory
from src.core.config import get_settings
from src.graph.executor import execute_multi_agent_chat
from src.pipeline.templates import get_pipeline
from src.services.session_store import (
    get_session as store_get_session,
    add_session_message as store_add_session_message,
    list_session_messages as store_list_session_messages,
)

logger = logging.getLogger(__name__)


async def run_pipeline(
    session_id: str,
    pipeline_id: str,
    request_id: str | None = None,
) -> dict[str, Any]:
    """执行指定流水线，从 session 获取上下文后调用多智能体协作图。"""
    pipeline = get_pipeline(pipeline_id)
    if not pipeline:
        logger.error("未找到流水线: %s", pipeline_id)
        return {"ok": False, "error": f"未知的流水线: {pipeline_id}"}

    sess = store_get_session(session_id)
    if not sess:
        return {"ok": False, "error": f"会话不存在: {session_id}"}

    case_id = sess.get("case_id", "")
    evidence_ids = sess.get("evidence_ids", [])
    user_message = f"请执行 \"{pipeline['name']}\" 流水线分析。{pipeline.get('description', '')}"
    session_memory: list[dict[str, str]] = []
    context_summary = ""

    try:
        store_add_session_message(session_id, "user", user_message)
        recent = store_list_session_messages(session_id)
        mem_max = get_settings().session_memory_single_msg_max_chars
        session_memory_raw = [
            {"role": (m.get("role") or "user"), "content": (m.get("content") or "")[:mem_max]}
            for m in (recent[:-1] if len(recent) > 1 else [])
            if (m.get("role") or "").lower() in ("user", "assistant") and (m.get("content") or "").strip()
        ]
        session_memory, _ = await compact_session_memory(
            session_memory_raw, session_id, case_id=case_id
        )
        if evidence_ids:
            context_summary = (
                f"【当前会话已关联证据】evidence_ids={evidence_ids}。"
                f"分析证据时请使用这些 ID 调用 evidence_* 工具。"
            )
        result = await execute_multi_agent_chat(
            case_id=case_id,
            session_id=session_id,
            user_message=user_message,
            session_memory=session_memory,
            context_summary=context_summary,
            evidence_ids=evidence_ids,
            request_id=request_id,
        )
        explanation = result.get("explanation", "")
        if explanation:
            store_add_session_message(session_id, "assistant", explanation)
        persist_chat_turn_workspace(
            (case_id or "").strip(),
            session_id,
            session_memory_before_run=session_memory,
            context_summary=context_summary,
            user_message=user_message,
            evidence_ids=evidence_ids,
            assistant_content=(explanation or "（无）").strip(),
            result=result,
            use_langgraph=True,
        )
        return {"ok": True, "data": result}
    except Exception as e:
        logger.error("流水线 %s 执行失败: %s", pipeline_id, e, exc_info=True)
        error_msg = f"流水线执行出错: {e}"
        store_add_session_message(session_id, "assistant", error_msg)
        persist_chat_turn_workspace(
            (case_id or "").strip(),
            session_id,
            session_memory_before_run=session_memory,
            context_summary=context_summary,
            user_message=user_message,
            evidence_ids=evidence_ids,
            assistant_content=error_msg,
            result={},
            use_langgraph=True,
            error=str(e),
        )
        return {"ok": False, "error": str(e)}
