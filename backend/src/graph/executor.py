"""
多智能体图执行入口。
提供 execute_multi_agent_chat()，支持流式/非流式两种模式。

多节点 Supervisor 循环架构 — 适配 route_after_supervisor 路由与 agent_results。
"""
import asyncio
import logging
import uuid
from typing import Any

from langchain_core.messages import HumanMessage

from src.agents.middleware.memory import load_case_memory
from src.core.config import get_settings
from src.graph.builder import get_compiled_graph
from src.graph.context import format_session_memory_for_graph
from src.skills.injector import build_skills_system_suffix, skills_injection_digest
from src.skills.llm_skill_router import merge_skill_ids_with_llm
from src.services.session_store import get_case as store_get_case
from src.skills.router import resolve_active_skill_ids

logger = logging.getLogger(__name__)


async def execute_multi_agent_chat(
    case_id: str,
    session_id: str,
    user_message: str,
    session_memory: list[dict[str, str]] | None = None,
    context_summary: str = "",
    request_id: str | None = None,
    stream_sink: asyncio.Queue | None = None,
    evidence_ids: list[str] | None = None,
    event_sink: asyncio.Queue | None = None,
    use_streaming: bool = False,
    skill_ids: list[str] | None = None,
    apply_skill_routing: bool = True,
    skills_inject_mode: str | None = None,
    skills_llm_routing: bool | None = None,
) -> dict[str, Any]:
    """
    执行 Supervisor 多智能体协作对话。

    Returns:
        {"explanation": str, "final_report": str, "agent_results": dict, ...}
        若启用 LangGraph checkpointer，另含 graph_thread_id（与传入的 request_id 或自动 UUID 一致）。
    """
    compiled = get_compiled_graph()

    case_memory = load_case_memory(case_id) if case_id else ""
    session_context = format_session_memory_for_graph(session_memory)
    ctx_summary = (context_summary or "").strip()

    case_row = store_get_case(case_id) if (case_id or "").strip() else None
    case_name = (case_row or {}).get("name") or ""
    raw_meta = (case_row or {}).get("meta")
    case_meta = raw_meta if isinstance(raw_meta, dict) else {}

    active_skill_ids = resolve_active_skill_ids(
        skill_ids,
        case_id,
        case_name=case_name,
        case_meta=case_meta,
        user_message=user_message,
        apply_routing=apply_skill_routing,
    )
    use_llm_route = (
        get_settings().skills_llm_routing_enabled
        if skills_llm_routing is None
        else skills_llm_routing
    )
    if use_llm_route:
        try:
            active_skill_ids = await merge_skill_ids_with_llm(active_skill_ids, user_message, case_id)
        except Exception as e:
            logger.warning("合并 LLM 技能推荐时跳过: %s", e)

    inj_mode = (skills_inject_mode or "").strip().lower()
    if inj_mode not in ("full", "catalog_only"):
        inj_mode = (get_settings().skills_default_inject_mode or "full").strip().lower()
    if inj_mode not in ("full", "catalog_only"):
        inj_mode = "full"

    _skill_state = {
        "active_skill_ids": active_skill_ids,
        "case_id": case_id,
        "skills_inject_mode": inj_mode,
    }
    # 仅用于 digest 长度估计；正文由各子节点按 neo_agents 调用 build_skills_system_suffix(..., for_agent=...) 注入，避免全量技能进入图状态
    skills_suffix_for_digest = build_skills_system_suffix(_skill_state)
    skills_digest = skills_injection_digest(active_skill_ids, len(skills_suffix_for_digest))

    graph_thread_id: str | None = None
    run_config: dict[str, Any] = {"recursion_limit": 25}
    if get_settings().langgraph_checkpoint_enabled:
        graph_thread_id = (request_id or "").strip() or str(uuid.uuid4())
        run_config["configurable"] = {"thread_id": graph_thread_id}

    initial_state: dict[str, Any] = {
        "messages": [HumanMessage(content=user_message)],
        "case_id": case_id,
        "session_id": session_id,
        "case_memory": case_memory,
        "user_message": user_message,
        "evidence_ids": evidence_ids or [],
        "session_context": session_context,
        "context_summary": ctx_summary,
        "active_skill_ids": active_skill_ids,
        "skills_injection_digest": skills_digest,
        "skills_system_suffix": "",
        "skills_inject_mode": inj_mode,
        "file_classifications": {},
        "agent_results": {},
        "final_report": "",
        "error": "",
        "use_streaming": use_streaming,
    }

    try:
        if use_streaming and stream_sink:
            final_state = await _run_with_streaming(
                compiled, initial_state, run_config, stream_sink, event_sink,
            )
        else:
            final_state = await compiled.ainvoke(initial_state, config=run_config)
    except Exception as e:
        logger.error("多智能体执行失败: %s", e, exc_info=True)
        if stream_sink:
            await stream_sink.put(("done", None))
        err: dict[str, Any] = {
            "explanation": f"多智能体协作执行出错: {e}",
            "final_report": "",
            "error": str(e),
        }
        if graph_thread_id is not None:
            err["graph_thread_id"] = graph_thread_id
        err["active_skill_ids"] = active_skill_ids
        err["skills_injection_digest"] = skills_digest
        err["skills_inject_mode"] = inj_mode
        return err

    final_report = final_state.get("final_report", "")
    all_messages = final_state.get("messages", [])
    last_content = all_messages[-1].content if all_messages else ""
    explanation = final_report or last_content

    if stream_sink:
        await stream_sink.put(("done", None))

    out: dict[str, Any] = {
        "explanation": explanation,
        "final_report": final_report,
        "agent_results": final_state.get("agent_results", {}),
        "file_classifications": final_state.get("file_classifications", {}),
    }
    if graph_thread_id is not None:
        out["graph_thread_id"] = graph_thread_id
    out["active_skill_ids"] = final_state.get("active_skill_ids") or []
    out["skills_injection_digest"] = final_state.get("skills_injection_digest") or ""
    out["skills_inject_mode"] = final_state.get("skills_inject_mode") or inj_mode
    return out


async def _run_with_streaming(
    compiled,
    initial_state: dict[str, Any],
    config: dict,
    stream_sink: asyncio.Queue,
    event_sink: asyncio.Queue | None,
) -> dict[str, Any]:
    """带流式输出的图执行。

    使用 astream(stream_mode=["custom", "values", "updates"])：
      - "custom"  捕获 get_stream_writer() 写入的自定义事件（token / agent_start / agent_end）
      - "updates" 每个节点提交后的状态补丁 → graph_step（可观测图进度）
      - "values"  每个节点完成后获取完整状态快照（最后一帧即为最终状态）
    """
    final_state = None

    async for mode, data in compiled.astream(
        initial_state, config=config, stream_mode=["custom", "values", "updates"],
    ):
        if mode == "custom":
            evt_type = data.get("type", "") if isinstance(data, dict) else ""
            if evt_type == "token":
                await stream_sink.put(("chunk", {
                    "agent": data.get("agent", ""),
                    "content": data.get("content", ""),
                }))
            elif evt_type == "agent_error":
                await stream_sink.put(("agent_error", data))
            elif evt_type in ("agent_start", "agent_end"):
                await stream_sink.put(("agent_event", data))
            elif evt_type == "tool_approval_required":
                await stream_sink.put(("tool_approval", data))
            elif evt_type == "tool_calls":
                await stream_sink.put(("tool_calls", data))

        elif mode == "updates":
            # data: { node_name: partial_state_update }
            if isinstance(data, dict):
                for node_name, patch in data.items():
                    if not isinstance(patch, dict):
                        continue
                    await stream_sink.put(("graph_step", {
                        "node": node_name,
                        "keys": list(patch.keys()),
                    }))

        elif mode == "values":
            if isinstance(data, dict):
                final_state = data

    if final_state is None:
        final_state = initial_state

    return final_state
