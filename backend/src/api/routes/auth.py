"""
认证路由：登录（JWT）、注册、当前用户信息、用户管理（管理员）。
"""
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from src.core.auth import (
    authenticate_user,
    get_current_user,
    create_jwt,
    register_user as auth_register_user,
    get_user_by_username,
    get_user_by_id,
    list_users as auth_list_users,
    update_user as auth_update_user,
    require_permission,
)
from src.core.exceptions import NeoException, CODE_UNAUTHORIZED
from src.models.user import User, Role, Permission

router = APIRouter(prefix="/auth", tags=["认证"])


class LoginBody(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str
    username: str
    role: str


@router.post("/login", response_model=LoginResponse)
def login(body: LoginBody):
    """登录：用户名密码换取 JWT。账户已禁用时返回 code=account_disabled。"""
    raw = get_user_by_username(body.username)
    if raw and not raw.get("enabled", True):
        raise NeoException(status_code=401, message="账户已禁用，请联系管理员", code="account_disabled")
    user = authenticate_user(body.username, body.password)
    if not user:
        raise NeoException(status_code=401, message="用户名或密码错误", code=CODE_UNAUTHORIZED)
    token = create_jwt(user.id, user.username, user.role.value)
    return LoginResponse(
        access_token=token,
        user_id=user.id,
        username=user.username,
        role=user.role.value,
    )


class RegisterBody(BaseModel):
    username: str = Field(..., min_length=3, max_length=32)
    password: str = Field(..., min_length=8)


class RegisterResponse(BaseModel):
    user_id: str
    username: str
    message: str = "注册成功，请联系管理员激活账户后再登录"


@router.post("/register", response_model=RegisterResponse)
def register(body: RegisterBody):
    """注册：创建普通用户，默认禁用，需管理员激活。"""
    if get_user_by_username(body.username):
        raise NeoException(status_code=400, message="用户名已存在", code="username_exists")
    user = auth_register_user(body.username, body.password, role=Role.member, enabled=False)
    return RegisterResponse(user_id=user.id, username=user.username)


class MeResponse(BaseModel):
    user_id: str
    username: str
    role: str
    project_ids: list[str]
    enabled: bool = True


@router.get("/me", response_model=MeResponse)
def me(current_user: Annotated[User, Depends(get_current_user)]):
    """当前用户信息（需 Bearer Token）。"""
    return MeResponse(
        user_id=current_user.id,
        username=current_user.username,
        role=current_user.role.value,
        project_ids=current_user.project_ids,
        enabled=current_user.enabled,
    )


# --- 用户管理（仅管理员） ---
class UserListItem(BaseModel):
    id: str
    username: str
    role: str
    enabled: bool


@router.get("/users", response_model=list[UserListItem])
def list_users(current_user: Annotated[User, Depends(require_permission(Permission.user_manage))]):
    """用户列表（仅管理员）。"""
    items = auth_list_users()
    return [UserListItem(id=u["id"], username=u["username"], role=u["role"], enabled=u["enabled"]) for u in items]


class UpdateUserBody(BaseModel):
    enabled: bool | None = None
    role: str | None = None
    password: str | None = None


@router.put("/users/{user_id}")
def update_user(
    user_id: str,
    body: UpdateUserBody,
    current_user: Annotated[User, Depends(require_permission(Permission.user_manage))],
):
    """更新用户：启用/禁用、角色、密码（仅管理员）。"""
    target = get_user_by_id(user_id)
    if not target:
        raise NeoException(status_code=404, message="用户不存在", code="user_not_found")
    role = Role(body.role) if body.role is not None else None
    auth_update_user(user_id, enabled=body.enabled, role=role, password=body.password)
    return {"ok": True, "user_id": user_id}


@router.get("/users/{user_id}/cases")
def list_user_cases(
    user_id: str,
    current_user: Annotated[User, Depends(require_permission(Permission.user_manage))],
):
    """查看指定用户的案件列表（仅管理员）；可据此进入该用户的会话与报告。"""
    target = get_user_by_id(user_id)
    if not target:
        raise NeoException(status_code=404, message="用户不存在", code="user_not_found")
    from src.services.session_store import list_cases_by_user
    items = list_cases_by_user(user_id)
    return {"items": items, "total": len(items), "username": target.username}
