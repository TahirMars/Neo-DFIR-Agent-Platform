"""
会话与案件存储：未配置 DATABASE_URL 时使用内存；配置后使用 PostgreSQL。
"""
from datetime import datetime, timezone
from typing import Any

from src.agents.middleware.memory import ensure_case_memory_template_if_missing
from src.core.ids import new_case_id, new_message_id, new_session_id

from src.db import get_db_session, is_configured
from src.db.models import CaseModel, SessionMessageModel, SessionModel

# 内存存储（未配置 DB 时使用）
_cases: dict[str, dict[str, Any]] = {}
_sessions: dict[str, dict[str, Any]] = {}
_session_messages: dict[str, list[dict[str, Any]]] = {}


def _row_to_case(row: CaseModel) -> dict[str, Any]:
    meta = getattr(row, "meta", None)
    if not isinstance(meta, dict):
        meta = {}
    return {
        "id": row.id,
        "project_id": row.project_id,
        "name": row.name,
        "created_by": row.created_by or "",
        "created_at": row.created_at.isoformat().replace("+00:00", "Z") if row.created_at else "",
        "meta": meta,
    }


def _row_to_session(row: SessionModel) -> dict[str, Any]:
    return {
        "id": row.id,
        "case_id": row.case_id,
        "evidence_ids": row.evidence_ids or [],
        "status": row.status or "pending",
        "report_artifact_id": row.report_artifact_id,
        "created_at": row.created_at.isoformat().replace("+00:00", "Z") if row.created_at else "",
    }


def _row_to_message(row: SessionMessageModel) -> dict[str, Any]:
    d: dict[str, Any] = {
        "id": row.id,
        "role": row.role,
        "content": row.content,
        "created_at": row.created_at.isoformat().replace("+00:00", "Z") if row.created_at else "",
    }
    if row.metadata_:
        d["metadata"] = row.metadata_
    return d


def create_case(project_id: str, name: str, created_by: str = "") -> dict[str, Any]:
    """创建案件；created_by 为创建人 user_id。"""
    if is_configured():
        from sqlalchemy import select
        from src.db.models import ProjectModel

        with get_db_session() as session:
            if session.scalar(select(ProjectModel).where(ProjectModel.id == project_id)) is None:
                proj = ProjectModel(id=project_id, name=project_id, slug=project_id)
                session.add(proj)
            case_id = new_case_id()
            case = CaseModel(id=case_id, project_id=project_id, name=name, created_by=created_by or None)
            session.add(case)
            session.flush()
            out = _row_to_case(case)
            ensure_case_memory_template_if_missing(out["id"])
            return out
    case_id = new_case_id()
    _cases[case_id] = {
        "id": case_id,
        "project_id": project_id,
        "name": name,
        "created_by": created_by,
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "meta": {},
    }
    ensure_case_memory_template_if_missing(case_id)
    return _cases[case_id]


def get_case(case_id: str) -> dict[str, Any] | None:
    """获取案件。"""
    if is_configured():
        with get_db_session() as session:
            row = session.get(CaseModel, case_id)
            return _row_to_case(row) if row else None
    return _cases.get(case_id)


def list_cases(project_id: str) -> list[dict[str, Any]]:
    """案件列表。"""
    if is_configured():
        with get_db_session() as session:
            from sqlalchemy import select
            rows = session.scalars(select(CaseModel).where(CaseModel.project_id == project_id)).all()
            return [_row_to_case(r) for r in rows]
    return [c for c in _cases.values() if c["project_id"] == project_id]


def list_cases_by_user(user_id: str) -> list[dict[str, Any]]:
    """按创建人列出案件。"""
    if is_configured():
        with get_db_session() as session:
            from sqlalchemy import select
            rows = session.scalars(select(CaseModel).where(CaseModel.created_by == user_id)).all()
            return [_row_to_case(r) for r in rows]
    return [c for c in _cases.values() if c.get("created_by") == user_id]


def delete_case(case_id: str) -> bool:
    """删除案件及其下所有会话与消息。"""
    if is_configured():
        with get_db_session() as session:
            case = session.get(CaseModel, case_id)
            if not case:
                return False
            session.delete(case)
            return True
    if case_id not in _cases:
        return False
    for sid in [s["id"] for s in _sessions.values() if s["case_id"] == case_id]:
        del _sessions[sid]
        _session_messages.pop(sid, None)
    del _cases[case_id]
    return True


def create_session(case_id: str) -> dict[str, Any]:
    """创建会话。"""
    if is_configured():
        with get_db_session() as session:
            if session.get(CaseModel, case_id) is None:
                raise ValueError("案件不存在")
            session_id = new_session_id()
            row = SessionModel(id=session_id, case_id=case_id, evidence_ids=[], status="pending")
            session.add(row)
            session.flush()
            return _row_to_session(row)
    if case_id not in _cases:
        raise ValueError("案件不存在")
    session_id = new_session_id()
    _sessions[session_id] = {
        "id": session_id,
        "case_id": case_id,
        "evidence_ids": [],
        "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    return _sessions[session_id]


def get_session(session_id: str) -> dict[str, Any] | None:
    """获取会话。"""
    if is_configured():
        with get_db_session() as session:
            row = session.get(SessionModel, session_id)
            return _row_to_session(row) if row else None
    return _sessions.get(session_id)


def list_sessions(case_id: str) -> list[dict[str, Any]]:
    """会话列表。"""
    if is_configured():
        with get_db_session() as session:
            from sqlalchemy import select
            rows = session.scalars(select(SessionModel).where(SessionModel.case_id == case_id)).all()
            return [_row_to_session(r) for r in rows]
    return [s for s in _sessions.values() if s["case_id"] == case_id]


def delete_session(session_id: str) -> bool:
    """删除会话及其消息。"""
    if is_configured():
        with get_db_session() as session:
            row = session.get(SessionModel, session_id)
            if not row:
                return False
            session.delete(row)
            return True
    if session_id not in _sessions:
        return False
    del _sessions[session_id]
    _session_messages.pop(session_id, None)
    return True


def add_evidence_to_session(session_id: str, evidence_id: str) -> None:
    """会话关联证据。"""
    if is_configured():
        with get_db_session() as session:
            row = session.get(SessionModel, session_id)
            if not row:
                raise ValueError("会话不存在")
            ids = list(row.evidence_ids or [])
            if evidence_id not in ids:
                ids.append(evidence_id)
                row.evidence_ids = ids
        return
    s = _sessions.get(session_id)
    if not s:
        raise ValueError("会话不存在")
    if evidence_id not in s["evidence_ids"]:
        s["evidence_ids"].append(evidence_id)


def update_session_status(session_id: str, status: str) -> None:
    """更新会话状态。"""
    if is_configured():
        with get_db_session() as session:
            row = session.get(SessionModel, session_id)
            if row:
                row.status = status
        return
    s = _sessions.get(session_id)
    if s:
        s["status"] = status


def set_report_artifact_id(session_id: str, artifact_id: str) -> None:
    """记录会话的报告 artifact_id。"""
    if is_configured():
        with get_db_session() as session:
            row = session.get(SessionModel, session_id)
            if row:
                row.report_artifact_id = artifact_id
        return
    s = _sessions.get(session_id)
    if s:
        s["report_artifact_id"] = artifact_id


def list_session_messages(session_id: str) -> list[dict[str, Any]]:
    """会话消息列表（按时间序）。"""
    if is_configured():
        with get_db_session() as session:
            from sqlalchemy import select
            rows = session.scalars(
                select(SessionMessageModel).where(SessionMessageModel.session_id == session_id).order_by(SessionMessageModel.created_at)
            ).all()
            return [_row_to_message(r) for r in rows]
    return _session_messages.get(session_id, [])


def add_session_message(
    session_id: str,
    role: str,
    content: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """追加一条消息（user / assistant）；返回新消息。"""
    if is_configured():
        with get_db_session() as session:
            if session.get(SessionModel, session_id) is None:
                raise ValueError("会话不存在")
            msg_id = new_message_id()
            row = SessionMessageModel(
                id=msg_id, session_id=session_id, role=role,
                content=content, metadata_=metadata,
            )
            session.add(row)
            session.flush()
            return _row_to_message(row)
    if session_id not in _session_messages:
        _session_messages[session_id] = []
    msg: dict[str, Any] = {
        "id": new_message_id(),
        "role": role,
        "content": content,
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    if metadata:
        msg["metadata"] = metadata
    _session_messages[session_id].append(msg)
    return msg
