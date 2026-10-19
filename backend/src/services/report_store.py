"""
报告存储：持久化报告 CRUD，支持 DB 与内存回退。
"""
import logging
from datetime import datetime, timezone
from typing import Any

from src.core.ids import new_report_id

from src.db import get_db_session, is_configured

logger = logging.getLogger(__name__)
from src.db.models import ReportModel

# 内存存储（未配置 DB 时使用）
_reports: dict[str, dict[str, Any]] = {}


def _row_to_report(row: ReportModel) -> dict[str, Any]:
    return {
        "id": row.id,
        "session_id": row.session_id,
        "case_id": row.case_id,
        "title": row.title,
        "content": row.content,
        "evidence_refs": row.evidence_refs or [],
        "created_at": row.created_at.isoformat().replace("+00:00", "Z") if row.created_at else "",
        "updated_at": row.updated_at.isoformat().replace("+00:00", "Z") if row.updated_at else "",
    }


def create_report(
    session_id: str,
    case_id: str,
    content: str,
    title: str = "分析报告",
    evidence_refs: list[dict[str, Any]] | None = None,
    *,
    from_pipeline: bool = False,
) -> dict[str, Any]:
    """创建报告。from_pipeline=True 时跳过会话存在性校验（流水线上下文已保证）。"""
    report_id = new_report_id()
    if is_configured():
        with get_db_session() as session:
            from src.db.models import SessionModel
            if not from_pipeline and session.get(SessionModel, session_id) is None:
                raise ValueError("会话不存在")
            row = ReportModel(
                id=report_id,
                session_id=session_id,
                case_id=case_id,
                title=title,
                content=content,
                evidence_refs=evidence_refs,
            )
            session.add(row)
            session.flush()
            return _row_to_report(row)
    _reports[report_id] = {
        "id": report_id,
        "session_id": session_id,
        "case_id": case_id,
        "title": title,
        "content": content,
        "evidence_refs": evidence_refs or [],
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "updated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    return _reports[report_id]


def get_report(report_id: str) -> dict[str, Any] | None:
    """获取单条报告。"""
    if is_configured():
        with get_db_session() as session:
            row = session.get(ReportModel, report_id)
            return _row_to_report(row) if row else None
    return _reports.get(report_id)


def list_reports_by_session(session_id: str) -> list[dict[str, Any]]:
    """按会话列出报告。"""
    if is_configured():
        with get_db_session() as session:
            from sqlalchemy import select
            rows = session.scalars(
                select(ReportModel).where(ReportModel.session_id == session_id).order_by(ReportModel.created_at.desc())
            ).all()
            return [_row_to_report(r) for r in rows]
    return [r for r in _reports.values() if r["session_id"] == session_id]


def list_reports_by_user(user_id: str, is_admin: bool = False) -> list[dict[str, Any]]:
    """按用户列出报告。admin 可见全部；member 可见自己创建案件下的报告（created_by）及 project_members 关联案件。"""
    if is_configured():
        with get_db_session() as session:
            from sqlalchemy import select
            from src.db.models import ProjectMemberModel, CaseModel

            case_ids = []

            if is_admin:
                # 管理员：全部案件下的报告
                case_rows = session.scalars(select(CaseModel.id)).all()
                case_ids = list(case_rows)
            else:
                # 成员：1) 自己创建的案件 2) project_members 关联项目下的案件
                created_case_rows = session.scalars(
                    select(CaseModel.id).where(CaseModel.created_by == user_id)
                ).all()
                case_ids = list(created_case_rows)

                pm_rows = session.scalars(
                    select(ProjectMemberModel.project_id).where(ProjectMemberModel.user_id == user_id)
                ).all()
                project_ids = list(pm_rows)
                if project_ids:
                    pm_case_rows = session.scalars(
                        select(CaseModel.id).where(CaseModel.project_id.in_(project_ids))
                    ).all()
                    for cid in pm_case_rows:
                        if cid not in case_ids:
                            case_ids.append(cid)

            if not case_ids:
                return []

            rows = session.scalars(
                select(ReportModel).where(ReportModel.case_id.in_(case_ids)).order_by(ReportModel.created_at.desc())
            ).all()
            return [_row_to_report(r) for r in rows]
    return list(_reports.values())


def update_report(report_id: str, title: str | None = None, content: str | None = None) -> dict[str, Any] | None:
    """更新报告。"""
    if is_configured():
        with get_db_session() as session:
            row = session.get(ReportModel, report_id)
            if not row:
                return None
            if title is not None:
                row.title = title
            if content is not None:
                row.content = content
            return _row_to_report(row)
    r = _reports.get(report_id)
    if not r:
        return None
    if title is not None:
        r["title"] = title
    if content is not None:
        r["content"] = content
    r["updated_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return r


def delete_report(report_id: str) -> bool:
    """删除报告。"""
    if is_configured():
        with get_db_session() as session:
            row = session.get(ReportModel, report_id)
            if not row:
                return False
            session.delete(row)
            return True
    if report_id not in _reports:
        return False
    del _reports[report_id]
    return True
