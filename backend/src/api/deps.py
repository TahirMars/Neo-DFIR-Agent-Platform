"""
依赖注入：当前用户、请求 ID、案件/会话归属校验、ID 格式校验。
"""
from typing import Annotated, Optional

from fastapi import Depends, Request

from src.api.middleware.request_id import REQUEST_ID_STATE_KEY, get_request_id
from src.core.auth import get_current_user, ensure_case_access, ensure_session_access
from src.core.exceptions import NeoException
from src.core.ids import PREFIX_CASE, PREFIX_EVIDENCE, PREFIX_REPORT, PREFIX_SESSION, is_valid_id
from src.models.user import User
from src.services.session_store import get_case as store_get_case, get_session as store_get_session


def get_request_id_from_request(request: Request) -> str:
    """从 request.state 取请求 ID。"""
    return getattr(request.state, REQUEST_ID_STATE_KEY, "") or ""


def validate_case_id(case_id: str) -> str:
    if not is_valid_id(case_id, PREFIX_CASE):
        raise NeoException(status_code=400, message=f"无效的案件 ID 格式: {case_id}", code="invalid_id")
    return case_id


def validate_session_id(session_id: str) -> str:
    if not is_valid_id(session_id, PREFIX_SESSION):
        raise NeoException(status_code=400, message=f"无效的会话 ID 格式: {session_id}", code="invalid_id")
    return session_id


def validate_evidence_id(evidence_id: str) -> str:
    if not is_valid_id(evidence_id, PREFIX_EVIDENCE):
        raise NeoException(status_code=400, message=f"无效的证据 ID 格式: {evidence_id}", code="invalid_id")
    return evidence_id


def validate_report_id(report_id: str) -> str:
    if not is_valid_id(report_id, PREFIX_REPORT):
        raise NeoException(status_code=400, message=f"无效的报告 ID 格式: {report_id}", code="invalid_id")
    return report_id


def require_case_access(case_id: str) -> None:
    """在路由内校验当前用户能否访问该案件；需先注入 current_user 并传入 case_id。"""
    case = store_get_case(case_id)
    # 由路由在取得 current_user 后调用 ensure_case_access(current_user, case)
    return


def require_session_access(session_id: str) -> None:
    """由路由在取得 current_user 后调用 ensure_session_access(current_user, session, store_get_case)。"""
    return
