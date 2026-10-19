"""
用户与角色模型（RBAC）。
当前为内存存储；后续可换 PostgreSQL。
"""
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class Role(str, Enum):
    """角色：admin 可访问全部，member 仅本人在的项目。"""
    admin = "admin"
    member = "member"


# 权限标识（与 API 域对应）
class Permission(str, Enum):
    project_read = "project:read"
    project_write = "project:write"
    case_read = "case:read"
    case_write = "case:write"
    evidence_upload = "evidence:upload"
    session_run = "session:run"
    report_read = "report:read"
    audit_read = "audit:read"
    pipeline_list = "pipeline:list"
    user_manage = "user:manage"  # 用户管理：列表、启用/禁用、查看用户案件


# 角色默认权限
ROLE_PERMISSIONS: dict[Role, set[Permission]] = {
    Role.admin: {
        Permission.project_read, Permission.project_write,
        Permission.case_read, Permission.case_write,
        Permission.evidence_upload, Permission.session_run,
        Permission.report_read, Permission.audit_read, Permission.pipeline_list,
        Permission.user_manage,
    },
    Role.member: {
        Permission.project_read, Permission.case_read, Permission.case_write,
        Permission.evidence_upload, Permission.session_run,
        Permission.report_read, Permission.audit_read, Permission.pipeline_list,
    },
}


class User(BaseModel):
    """当前用户（认证后注入）。"""
    id: str
    username: str
    role: Role = Role.member
    project_ids: list[str] = Field(default_factory=list)  # member 仅能访问这些项目；admin 忽略
    enabled: bool = True  # 是否允许登录；禁用后无法登录

    def has_permission(self, perm: Permission) -> bool:
        return perm in ROLE_PERMISSIONS.get(self.role, set())

    def can_access_project(self, project_id: str) -> bool:
        if self.role == Role.admin:
            return True
        if project_id in self.project_ids:
            return True
        # 普通用户未分配项目时允许访问默认项目 proj1，以便新建案件
        if self.role == Role.member and not self.project_ids and project_id == "proj1":
            return True
        return False

    def can_access_case(self, case: dict[str, Any]) -> bool:
        return self.can_access_project(case.get("project_id", ""))
