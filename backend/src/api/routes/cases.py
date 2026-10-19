"""
案件路由（P0 最小集合，M1 对接 session_store，RBAC）。
"""
from typing import Annotated

from fastapi import APIRouter, Body, Depends

from src.api.deps import validate_case_id
from src.core.auth import ensure_case_access, ensure_case_can_delete, require_permission
from src.core.exceptions import CODE_FORBIDDEN, CODE_NOT_FOUND, NeoException
from src.tools.evidence.tools import delete_evidence_for_case
from src.models.user import Permission, User
from src.services.session_store import (
    create_case as store_create_case,
    delete_case as store_delete_case,
    get_case as store_get_case,
    list_cases as store_list_cases,
    list_cases_by_user as store_list_cases_by_user,
)

router = APIRouter(tags=["案件"])


@router.get("/projects/{project_id}/cases")
def list_cases(
    project_id: str,
    current_user: Annotated[User, Depends(require_permission(Permission.case_read))],
):
    """案件列表（我的案件）；校验 project 归属。仅返回当前用户自己创建的案件；管理员查看他人案件需通过「用户管理 → 查看案件」。"""
    if not current_user.can_access_project(project_id):
        raise NeoException(status_code=403, message="无此项目访问权限", code=CODE_FORBIDDEN)
    items = store_list_cases(project_id)
    items = [c for c in items if c.get("created_by") == current_user.id]
    return {"items": items, "total": len(items)}


@router.post("/projects/{project_id}/cases")
def create_case(
    project_id: str,
    current_user: Annotated[User, Depends(require_permission(Permission.case_write))],
    body: dict = Body(default_factory=dict),
):
    """创建案件；校验 project 归属。"""
    if not current_user.can_access_project(project_id):
        raise NeoException(status_code=403, message="无此项目访问权限", code=CODE_FORBIDDEN)
    name = body.get("name", "未命名案件")
    case = store_create_case(project_id, name, created_by=current_user.id)
    return case


@router.get("/cases/{case_id}")
def get_case(
    case_id: Annotated[str, Depends(validate_case_id)],
    current_user: Annotated[User, Depends(require_permission(Permission.case_read))],
):
    """案件详情；校验 project 归属。"""
    case = store_get_case(case_id)
    if not case:
        raise NeoException(status_code=404, message="案件不存在", code=CODE_NOT_FOUND)
    ensure_case_access(current_user, case)
    return case


@router.delete("/cases/{case_id}")
def delete_case(
    case_id: Annotated[str, Depends(validate_case_id)],
    current_user: Annotated[User, Depends(require_permission(Permission.case_write))],
):
    """删除案件（仅创建者或管理员）；同时删除其下所有会话。"""
    case = store_get_case(case_id)
    if not case:
        raise NeoException(status_code=404, message="案件不存在", code=CODE_NOT_FOUND)
    ensure_case_can_delete(current_user, case)
    delete_evidence_for_case(case_id)
    store_delete_case(case_id)
    return {"ok": True, "case_id": case_id}
