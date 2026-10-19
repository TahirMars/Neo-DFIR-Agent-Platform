"""
会话、流水线触发路由（P0 最小集合，M1/M2 对接 session_store + Evidence MCP + 流水线引擎，RBAC）。
与 AI 对话：支持流式与非流式输出；无证据时也可与模型对话获取事件响应建议。
"""
import asyncio
from typing import Annotated

from fastapi import APIRouter, Body, Depends, Request
from fastapi.responses import StreamingResponse

from src.agents.common import AgentContext
from src.agents.middleware.session_persistence import persist_chat_turn_workspace
from src.agents.middleware.summarization import compact_session_memory
from src.agents.runtime import run_agent
from src.api.deps import validate_case_id, validate_session_id
from src.graph.executor import execute_multi_agent_chat
from src.core.auth import ensure_case_access, ensure_session_access, require_permission
from src.core.config import get_settings
from src.core.audit import get_session_audit as get_audit_entries
from src.core.exceptions import CODE_NOT_FOUND, NeoException
from src.api.stream_envelope import StreamKind, format_sse_data, new_run_id
from src.core.hitl import approve_tool, get_pending
from src.tools.evidence.tools import (
    session_create as mcp_session_create,
    workspace_list_files,
    workspace_read,
)
from src.models.user import Permission, User
from src.pipeline.engine import run_pipeline as engine_run_pipeline

from src.services.session_store import (
    create_session as store_create_session,
    delete_session as store_delete_session,
    get_case as store_get_case,
    get_session as store_get_session,
    list_sessions as store_list_sessions,
    list_session_messages as store_list_session_messages,
    add_session_message as store_add_session_message,
)

# 与 AI 对话时使用的系统提示（事件响应建议，无证据时也可给出通用建议）
CHAT_SYSTEM_PROMPT = """你是数字取证与事件响应（DFIR）领域的助手。用户可能尚未上传证据，或正在咨询事件响应流程与建议。

请基于用户的问题，提供简洁、可操作的事件响应建议，例如：
- 准备阶段：资产清单、备份与恢复流程、预案与演练
- 检测与识别：日志与监控、IOC 与 TTP、时间线梳理
- 遏制与根除：隔离、补丁与加固、恶意代码清除
- 恢复与复盘：业务恢复、证据保留、事后总结与改进

若用户已描述具体场景（如勒索软件、数据泄露、入侵痕迹），请针对该场景给出步骤化建议。回答使用中文，条理清晰，必要时分点或分步骤。"""

router = APIRouter(tags=["会话"])


@router.get("/cases/{case_id}/sessions")
def list_sessions(
    case_id: Annotated[str, Depends(validate_case_id)],
    current_user: Annotated[User, Depends(require_permission(Permission.case_read))],
):
    """会话列表；校验 case 归属。"""
    case = store_get_case(case_id)
    if not case:
        raise NeoException(status_code=404, message="案件不存在", code=CODE_NOT_FOUND)
    ensure_case_access(current_user, case)
    items = store_list_sessions(case_id)
    return {"items": items, "total": len(items)}


@router.post("/cases/{case_id}/sessions")
def create_session(
    case_id: Annotated[str, Depends(validate_case_id)],
    current_user: Annotated[User, Depends(require_permission(Permission.case_write))],
    body: dict | None = None,
):
    """创建会话（经 MCP session.create）；校验 case 归属。"""
    case = store_get_case(case_id)
    if not case:
        raise NeoException(status_code=404, message="案件不存在", code=CODE_NOT_FOUND)
    ensure_case_access(current_user, case)
    envelope = mcp_session_create({"case_id": case_id})
    if not envelope.get("ok"):
        raise NeoException(status_code=400, message="; ".join(envelope.get("errors", ["创建失败"])))
    session_id = envelope["data"]["session_id"]
    sess = store_get_session(session_id)
    return sess or {"id": session_id, "case_id": case_id, "evidence_ids": [], "status": "pending"}


@router.get("/sessions/{session_id}")
def get_session(
    session_id: Annotated[str, Depends(validate_session_id)],
    current_user: Annotated[User, Depends(require_permission(Permission.case_read))],
):
    """会话详情；校验会话归属。"""
    sess = store_get_session(session_id)
    if not sess:
        raise NeoException(status_code=404, message="会话不存在", code=CODE_NOT_FOUND)
    ensure_session_access(current_user, sess, store_get_case)
    return sess


@router.delete("/sessions/{session_id}")
def delete_session(
    session_id: Annotated[str, Depends(validate_session_id)],
    current_user: Annotated[User, Depends(require_permission(Permission.case_write))],
):
    """删除会话及其消息；校验会话归属。"""
    sess = store_get_session(session_id)
    if not sess:
        raise NeoException(status_code=404, message="会话不存在", code=CODE_NOT_FOUND)
    ensure_session_access(current_user, sess, store_get_case)
    if not store_delete_session(session_id):
        raise NeoException(status_code=500, message="删除失败")
    return {"ok": True, "session_id": session_id}


@router.post("/sessions/{session_id}/run")
async def run_pipeline(
    session_id: Annotated[str, Depends(validate_session_id)],
    request: Request,
    current_user: Annotated[User, Depends(require_permission(Permission.session_run))],
    body: dict | None = None,
):
    """触发流水线执行（M2）；校验会话归属。"""
    sess = store_get_session(session_id)
    if not sess:
        raise NeoException(status_code=404, message="会话不存在", code=CODE_NOT_FOUND)
    ensure_session_access(current_user, sess, store_get_case)
    pipeline_id = (body or {}).get("pipeline_id") or "single_host_quick"
    request_id = getattr(request.state, "request_id", None) or request.headers.get("X-Request-Id")
    task = asyncio.create_task(engine_run_pipeline(session_id, pipeline_id, request_id))
    task.add_done_callback(lambda t: None)
    return {"session_id": session_id, "status": "accepted", "message": "流水线已提交执行"}


@router.get("/sessions/{session_id}/status")
def get_session_status(
    session_id: Annotated[str, Depends(validate_session_id)],
    current_user: Annotated[User, Depends(require_permission(Permission.case_read))],
):
    """流水线执行状态（M2）；校验会话归属。"""
    sess = store_get_session(session_id)
    if not sess:
        raise NeoException(status_code=404, message="会话不存在", code=CODE_NOT_FOUND)
    ensure_session_access(current_user, sess, store_get_case)
    status = sess.get("status", "pending")
    progress = 100 if status == "completed" else (50 if status == "running" else 0)
    return {"session_id": session_id, "status": status, "progress": progress}


@router.get("/sessions/{session_id}/audit")
def get_session_audit(
    session_id: Annotated[str, Depends(validate_session_id)],
    current_user: Annotated[User, Depends(require_permission(Permission.audit_read))],
):
    """会话级审计日志（M2）；RBAC，校验会话归属。"""
    sess = store_get_session(session_id)
    if not sess:
        raise NeoException(status_code=404, message="会话不存在", code=CODE_NOT_FOUND)
    ensure_session_access(current_user, sess, store_get_case)
    entries = get_audit_entries(session_id)
    return {"session_id": session_id, "items": entries, "total": len(entries)}


@router.get("/sessions/{session_id}/pending-approvals")
def list_pending_approvals(
    session_id: Annotated[str, Depends(validate_session_id)],
    current_user: Annotated[User, Depends(require_permission(Permission.case_read))],
):
    """P1 HITL: 获取会话下待审批的工具调用列表。"""
    sess = store_get_session(session_id)
    if not sess:
        raise NeoException(status_code=404, message="会话不存在", code=CODE_NOT_FOUND)
    ensure_session_access(current_user, sess, store_get_case)
    items = get_pending(session_id)
    return {"session_id": session_id, "items": items}


@router.post("/sessions/{session_id}/approve-tool")
def approve_tool_call(
    session_id: Annotated[str, Depends(validate_session_id)],
    current_user: Annotated[User, Depends(require_permission(Permission.case_write))],
    body: dict = Body(default_factory=dict),
):
    """P1 HITL: 批准待执行的工具调用。body: {tool, args}"""
    sess = store_get_session(session_id)
    if not sess:
        raise NeoException(status_code=404, message="会话不存在", code=CODE_NOT_FOUND)
    ensure_session_access(current_user, sess, store_get_case)
    tool_name = body.get("tool", "").strip()
    args = body.get("args") or {}
    if not tool_name:
        raise NeoException(status_code=400, message="tool 不能为空", code="invalid_input")
    result = approve_tool(session_id, tool_name, args)
    if not result.get("ok"):
        raise NeoException(status_code=400, message=result.get("error", "审批失败"))
    return result


@router.get("/sessions/{session_id}/workspace/files")
def list_workspace_files(
    session_id: Annotated[str, Depends(validate_session_id)],
    current_user: Annotated[User, Depends(require_permission(Permission.case_read))],
):
    """列出会话工作区文件（含 conversation_history.md、tool_results/*、snapshots/*、artifacts/* 等）。"""
    sess = store_get_session(session_id)
    if not sess:
        raise NeoException(status_code=404, message="会话不存在", code=CODE_NOT_FOUND)
    ensure_session_access(current_user, sess, store_get_case)
    case_id = sess.get("case_id") or ""
    r = workspace_list_files(case_id, session_id)
    if not r.get("ok"):
        raise NeoException(status_code=500, message=r.get("error", "未知错误"))
    return {"session_id": session_id, "items": r.get("files", [])}


@router.get("/sessions/{session_id}/workspace/files/{file_path:path}")
def read_workspace_file(
    session_id: Annotated[str, Depends(validate_session_id)],
    file_path: str,
    current_user: Annotated[User, Depends(require_permission(Permission.case_read))],
):
    """P2: 读取工作区文件内容。"""
    sess = store_get_session(session_id)
    if not sess:
        raise NeoException(status_code=404, message="会话不存在", code=CODE_NOT_FOUND)
    ensure_session_access(current_user, sess, store_get_case)
    case_id = sess.get("case_id") or ""
    r = workspace_read(case_id, session_id, file_path)
    if not r.get("ok"):
        raise NeoException(status_code=404, message=r.get("error", "文件不存在"), code=CODE_NOT_FOUND)
    return {"path": file_path, "content": r.get("content", ""), "truncated": r.get("truncated", False)}


@router.get("/sessions/{session_id}/messages")
def get_session_messages(
    session_id: Annotated[str, Depends(validate_session_id)],
    current_user: Annotated[User, Depends(require_permission(Permission.case_read))],
):
    """会话消息列表（与 AI 对话历史）；校验会话归属。"""
    sess = store_get_session(session_id)
    if not sess:
        raise NeoException(status_code=404, message="会话不存在", code=CODE_NOT_FOUND)
    ensure_session_access(current_user, sess, store_get_case)
    items = store_list_session_messages(session_id)
    return {"session_id": session_id, "items": items, "total": len(items)}


def _build_chat_messages(session_id: str) -> list[dict[str, str]]:
    """构建对话消息：系统提示 + 近期历史（含刚追加的用户消息）。"""
    mem_max = get_settings().session_memory_single_msg_max_chars
    messages: list[dict[str, str]] = [{"role": "system", "content": CHAT_SYSTEM_PROMPT}]
    recent = store_list_session_messages(session_id)
    for m in recent:
        role = (m.get("role") or "user").lower()
        if role not in ("user", "assistant"):
            continue
        msg_content = (m.get("content") or "").strip()
        if msg_content:
            messages.append({"role": role, "content": msg_content[:mem_max]})
    return messages


@router.post("/sessions/{session_id}/chat")
async def send_chat(
    request: Request,
    session_id: Annotated[str, Depends(validate_session_id)],
    current_user: Annotated[User, Depends(require_permission(Permission.case_read))],
    body: dict = Body(default_factory=dict),
):
    """发送一条用户消息并返回 AI 回复；支持流式（body.stream=true）与非流式。"""
    sess = store_get_session(session_id)
    if not sess:
        raise NeoException(status_code=404, message="会话不存在", code=CODE_NOT_FOUND)
    ensure_session_access(current_user, sess, store_get_case)
    content = (body.get("content") or "").strip()
    if not content:
        raise NeoException(status_code=400, message="消息内容不能为空", code="invalid_input")

    user_msg = store_add_session_message(session_id, "user", content)
    case_id = (sess.get("case_id") or "").strip()
    session_evidence_ids = sess.get("evidence_ids") or []
    body_evidence_ids = [e for e in (body.get("evidence_ids") or []) if isinstance(e, str) and e.strip()]
    if body_evidence_ids:
        evidence_ids = [eid for eid in body_evidence_ids if eid in session_evidence_ids] or session_evidence_ids
    else:
        evidence_ids = session_evidence_ids
    recent = store_list_session_messages(session_id)
    mem_max = get_settings().session_memory_single_msg_max_chars
    # 会话记忆：不含本条用户消息（已作为 user_message 传入 Agent）
    session_memory_raw = [
        {"role": (m.get("role") or "user"), "content": (m.get("content") or "")[:mem_max]}
        for m in (recent[:-1] if len(recent) > 1 else [])
        if (m.get("role") or "").lower() in ("user", "assistant") and (m.get("content") or "").strip()
    ]
    # P0: 上下文自动摘要与压缩（超过阈值时）
    session_memory, _ = await compact_session_memory(
        session_memory_raw, session_id, case_id=case_id
    )
    context_summary = ""
    if evidence_ids:
        context_summary = f"【当前会话已关联证据】evidence_ids={evidence_ids}。分析证据时请使用这些 ID 调用 evidence_* 工具。"
    request_id = getattr(request.state, "request_id", None) or request.headers.get("X-Request-Id")
    context = AgentContext(
        case_id=case_id,
        session_id=session_id,
        user_message=content,
        session_memory=session_memory,
    )

    # 使用 langgraph 多智能体协作（可通过 body.use_langgraph 控制）
    use_langgraph = body.get("use_langgraph", True)  # 默认启用
    stream_requested = body.get("stream") is True
    skill_ids_raw = body.get("skill_ids") or []
    skill_ids = [
        str(s).strip()
        for s in skill_ids_raw
        if isinstance(s, str) and str(s).strip()
    ][:24]
    apply_skill_routing = body.get("apply_skill_routing", True)
    _sim = (body.get("skills_inject_mode") or "").strip().lower()
    skills_inject_mode = _sim if _sim in ("full", "catalog_only") else None
    skills_llm_routing = body.get("skills_llm_routing")
    if skills_llm_routing is not None:
        skills_llm_routing = bool(skills_llm_routing)

    if stream_requested:
        async def sse_stream():
            import time

            run_id = new_run_id()
            seq_box = [0]

            def emit(kind: str, payload: dict | None = None) -> str:
                seq_box[0] += 1
                return format_sse_data(run_id, seq_box[0], kind, payload)

            try:
                yield emit(StreamKind.RUN_STARTED, {"session_id": session_id})
                if use_langgraph:
                    stream_queue: asyncio.Queue = asyncio.Queue()
                    task = asyncio.create_task(
                        execute_multi_agent_chat(
                            case_id=case_id,
                            session_id=session_id,
                            user_message=content,
                            session_memory=session_memory,
                            context_summary=context_summary,
                            request_id=request_id,
                            stream_sink=stream_queue,
                            evidence_ids=evidence_ids,
                            event_sink=stream_queue,
                            use_streaming=True,
                            skill_ids=skill_ids,
                            apply_skill_routing=apply_skill_routing,
                            skills_inject_mode=skills_inject_mode,
                            skills_llm_routing=skills_llm_routing,
                        )
                    )
                    agent_meta_map = {
                        "supervisor": ("Neo智能体", "\U0001F916"),
                        "forensic_agent": ("取证分析", "\U0001F50D"),
                        "sample_agent": ("样本分析", "\U0001F9EC"),
                        "report_generator": ("报告生成", "\U0001F4CB"),
                        "general_chat": ("DFIR专家", "\U0001F4AC"),
                    }
                    collected_phases: dict[str, dict] = {}
                    phase_order: list[str] = []

                    while True:
                        try:
                            kind, payload = await asyncio.wait_for(stream_queue.get(), timeout=0.5)
                        except asyncio.TimeoutError:
                            if task.done():
                                break
                            yield ": keepalive\n\n"
                            continue
                        if kind == "done":
                            break
                        if kind == "graph_step" and payload:
                            yield emit(StreamKind.GRAPH_STEP, dict(payload))
                            continue
                        if kind == "agent_error" and payload:
                            agent_name = payload.get("agent", "")
                            err_msg = payload.get("message", "")
                            err_content = f"⚠️ 智能体执行失败：{err_msg}\n\n请检查网络连接或稍后重试。"
                            if agent_name:
                                if agent_name not in collected_phases:
                                    phase_order.append(agent_name)
                                    label, icon = agent_meta_map.get(agent_name, (agent_name, "\u2699\uFE0F"))
                                    collected_phases[agent_name] = {
                                        "agent": agent_name, "label": label, "icon": icon,
                                        "status": "error", "content": err_content,
                                        "start_time": time.time(), "end_time": time.time(),
                                    }
                                else:
                                    collected_phases[agent_name]["content"] += (
                                        ("\n\n" if collected_phases[agent_name]["content"] else "") + err_content
                                    )
                                    collected_phases[agent_name]["status"] = "error"
                            yield emit(
                                StreamKind.AGENT_ERROR,
                                {"agent": agent_name, "message": err_msg},
                            )
                            continue
                        if kind == "tool_approval" and payload:
                            yield emit(
                                StreamKind.HITL_REQUIRED,
                                {
                                    "approval_id": payload.get("approval_id", ""),
                                    "tool": payload.get("tool", ""),
                                    "args": payload.get("args") or {},
                                },
                            )
                            continue
                        if kind == "chunk" and payload:
                            yield emit(
                                StreamKind.LLM_DELTA,
                                {
                                    "agent": payload.get("agent", ""),
                                    "content": payload.get("content", ""),
                                },
                            )
                            agent_name = payload.get("agent", "")
                            if agent_name and agent_name in collected_phases:
                                collected_phases[agent_name]["content"] += payload.get("content", "")
                            continue
                        if kind == "agent_event" and payload:
                            evt_type = payload.get("type", "")
                            agent_name = payload.get("agent", "")
                            if evt_type == "agent_start" and agent_name:
                                yield emit(StreamKind.AGENT_START, {"agent": agent_name})
                                label, icon = agent_meta_map.get(agent_name, (agent_name, "\u2699\uFE0F"))
                                if agent_name not in collected_phases:
                                    phase_order.append(agent_name)
                                    collected_phases[agent_name] = {
                                        "agent": agent_name, "label": label, "icon": icon,
                                        "status": "running", "content": "",
                                        "start_time": time.time(),
                                    }
                                else:
                                    collected_phases[agent_name]["status"] = "running"
                            elif evt_type == "agent_end" and agent_name:
                                yield emit(StreamKind.AGENT_END, {"agent": agent_name})
                                if agent_name in collected_phases:
                                    collected_phases[agent_name]["status"] = "completed"
                                    collected_phases[agent_name]["end_time"] = time.time()
                            continue
                        if kind == "tool_calls" and payload:
                            agent_name = payload.get("agent", "")
                            tool_calls = payload.get("tool_calls", [])
                            yield emit(
                                StreamKind.TOOL_CALLS,
                                {"agent": agent_name, "tool_calls": tool_calls},
                            )
                            if agent_name and agent_name in collected_phases and tool_calls:
                                collected_phases[agent_name]["tool_calls"] = tool_calls
                            continue

                    result = await task
                    assistant_content = (result.get("explanation") or "").strip() or "（无回复内容）"
                    phases_list = [collected_phases[a] for a in phase_order if a in collected_phases]
                    for p in phases_list:
                        if p.get("status") != "completed":
                            p["status"] = "completed"
                            p.setdefault("end_time", time.time())
                    agent_results = result.get("agent_results") or {}
                    msg_metadata = {
                        "active_skill_ids": result.get("active_skill_ids") or [],
                        "skills_injection_digest": result.get("skills_injection_digest") or "",
                        "skills_inject_mode": result.get("skills_inject_mode") or "",
                    }
                    if phases_list:
                        msg_metadata["agent_phases"] = phases_list
                    if agent_results:
                        msg_metadata["agent_results"] = agent_results
                    assistant_msg = store_add_session_message(
                        session_id, "assistant", assistant_content, metadata=msg_metadata
                    )
                    persist_chat_turn_workspace(
                        case_id,
                        session_id,
                        session_memory_before_run=session_memory,
                        context_summary=context_summary,
                        user_message=content,
                        evidence_ids=evidence_ids,
                        assistant_content=assistant_content,
                        result=result,
                        use_langgraph=True,
                    )
                    yield emit(
                        StreamKind.RUN_COMPLETED,
                        {
                            "message_id": assistant_msg.get("id"),
                            "finish_reason": "stop",
                            "agent_phases": phases_list,
                            "active_skill_ids": result.get("active_skill_ids") or [],
                            "skills_injection_digest": result.get("skills_injection_digest") or "",
                            "skills_inject_mode": result.get("skills_inject_mode") or "",
                        },
                    )
                else:
                    # 单 Agent 非 LangGraph：run_agent 内 model.astream，逐段推送 llm.delta（P2）
                    stream_queue: asyncio.Queue = asyncio.Queue()

                    def on_token(s: str) -> None:
                        stream_queue.put_nowait(("chunk", {"agent": "default", "content": s}))

                    task = asyncio.create_task(
                        run_agent(
                            "default",
                            context,
                            request_id=request_id,
                            enable_thinking=True,
                            on_token=on_token,
                        )
                    )
                    yield emit(StreamKind.AGENT_START, {"agent": "default"})
                    while True:
                        try:
                            kind, payload = await asyncio.wait_for(stream_queue.get(), timeout=0.5)
                        except asyncio.TimeoutError:
                            if task.done():
                                while True:
                                    try:
                                        kind, payload = stream_queue.get_nowait()
                                    except asyncio.QueueEmpty:
                                        break
                                    if kind == "chunk" and payload:
                                        yield emit(
                                            StreamKind.LLM_DELTA,
                                            {
                                                "agent": "default",
                                                "content": payload.get("content", ""),
                                            },
                                        )
                                break
                            yield ": keepalive\n\n"
                            continue
                        if kind == "chunk" and payload:
                            yield emit(
                                StreamKind.LLM_DELTA,
                                {
                                    "agent": "default",
                                    "content": payload.get("content", ""),
                                },
                            )
                    result = await task
                    assistant_content = (result.get("explanation") or "").strip() or "（无回复内容）"
                    assistant_msg = store_add_session_message(session_id, "assistant", assistant_content)
                    persist_chat_turn_workspace(
                        case_id,
                        session_id,
                        session_memory_before_run=session_memory,
                        context_summary=context_summary,
                        user_message=content,
                        evidence_ids=evidence_ids,
                        assistant_content=assistant_content,
                        result=result,
                        use_langgraph=False,
                    )
                    yield emit(StreamKind.AGENT_END, {"agent": "default"})
                    yield emit(
                        StreamKind.RUN_COMPLETED,
                        {
                            "message_id": assistant_msg.get("id"),
                            "finish_reason": "stop",
                            "agent_phases": [],
                        },
                    )
            except Exception as e:
                err_text = f"当前对话服务暂时不可用：{e!s}"
                store_add_session_message(session_id, "assistant", err_text)
                persist_chat_turn_workspace(
                    case_id,
                    session_id,
                    session_memory_before_run=session_memory,
                    context_summary=context_summary,
                    user_message=content,
                    evidence_ids=evidence_ids,
                    assistant_content=err_text,
                    result={},
                    use_langgraph=use_langgraph,
                    error=str(e),
                )
                yield emit(StreamKind.RUN_FAILED, {"error": err_text})

        return StreamingResponse(
            sse_stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # 非流式：通过 Agent 执行（含 MCP 工具调用）
    if use_langgraph:
        # 使用 langgraph 多智能体
        result = await execute_multi_agent_chat(
            case_id=case_id,
            session_id=session_id,
            user_message=content,
            session_memory=session_memory,
            context_summary=context_summary,
            request_id=request_id,
            evidence_ids=evidence_ids,
            skill_ids=skill_ids,
            apply_skill_routing=apply_skill_routing,
        )
    else:
        result = await run_agent("default", context, request_id=request_id, enable_thinking=False)
    
    assistant_content = (result.get("explanation") or "").strip() or "（无回复内容）"
    if use_langgraph:
        assistant_msg = store_add_session_message(
            session_id,
            "assistant",
            assistant_content,
            metadata={
                "active_skill_ids": result.get("active_skill_ids") or [],
                "skills_injection_digest": result.get("skills_injection_digest") or "",
                "skills_inject_mode": result.get("skills_inject_mode") or "",
            },
        )
    else:
        assistant_msg = store_add_session_message(session_id, "assistant", assistant_content)
    persist_chat_turn_workspace(
        case_id,
        session_id,
        session_memory_before_run=session_memory,
        context_summary=context_summary,
        user_message=content,
        evidence_ids=evidence_ids,
        assistant_content=assistant_content,
        result=result,
        use_langgraph=use_langgraph,
    )
    out: dict = {"user_message": user_msg, "assistant_message": assistant_msg}
    if use_langgraph:
        out["active_skill_ids"] = result.get("active_skill_ids") or []
        out["skills_injection_digest"] = result.get("skills_injection_digest") or ""
        out["skills_inject_mode"] = result.get("skills_inject_mode") or ""
    return out
