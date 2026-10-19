"""
项目/空间路由（P0 最小集合，RBAC）。
"""
from typing import Annotated

from fastapi import APIRouter, Depends

from src.core.auth import get_current_user, require_permission
from src.models.user import Permission, User

router = APIRouter(prefix="/projects", tags=["项目"])


@router.get("")
def list_projects(current_user: Annotated[User, Depends(require_permission(Permission.project_read))]):
    """项目列表（当前用户可见）；RBAC。普通用户若无项目则返回默认项目，以便可新建案件。"""
    # 占位：后续从 DB 按 current_user.project_ids 或 admin 查全部
    if current_user.role.value == "admin":
        return {"items": [{"id": "proj1", "name": "默认项目"}], "total": 1}
    pids = current_user.project_ids or []
    if not pids:
        # 普通用户未分配项目时给一个默认项目，否则无法新建案件
        pids = ["proj1"]
    return {"items": [{"id": pid, "name": f"项目 {pid}"} for pid in pids], "total": len(pids)}


@router.post("")
def create_project(current_user: Annotated[User, Depends(require_permission(Permission.project_write))], body: dict | None = None):
    """创建项目；RBAC。"""
    name = (body or {}).get("name", "未命名项目")
    # 占位：后续写 DB 并返回 id
    return {"id": "proj-new", "name": name}
