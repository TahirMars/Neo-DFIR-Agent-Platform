"""
RBAC、JWT 校验与用户权限。
未配置 DATABASE_URL 时使用内存；配置后使用 PostgreSQL。
"""
import time
import uuid
from typing import Annotated, Optional

import bcrypt
import jwt as pyjwt
from fastapi import Depends, Header
from sqlalchemy import select

from src.core.config import get_settings
from src.core.exceptions import CODE_FORBIDDEN, CODE_UNAUTHORIZED, NeoException
from src.db import get_db_session, is_configured
from src.db.models import ProjectMemberModel, ProjectModel, UserModel
from src.models.user import Permission, Role, User, ROLE_PERMISSIONS

# 内存用户存储（未配置 DB 时使用）
_users: dict[str, dict] = {}
_users_by_username: dict[str, str] = {}  # username -> user_id


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("ascii"))
    except Exception:
        return False


def create_jwt(user_id: str, username: str, role: str) -> str:
    settings = get_settings()
    payload = {"sub": user_id, "username": username, "role": role, "exp": int(time.time()) + settings.jwt_expire_seconds}
    return pyjwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_jwt(token: str) -> Optional[dict]:
    settings = get_settings()
    try:
        return pyjwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except Exception:
        return None


def _get_project_ids_for_user(session, user_id: str) -> list[str]:
    """从 project_members 表取用户的 project_ids。"""
    rows = session.scalars(select(ProjectMemberModel.project_id).where(ProjectMemberModel.user_id == user_id)).all()
    return list(rows)


def register_user(
    username: str,
    password: str,
    role: Role = Role.member,
    project_ids: Optional[list[str]] = None,
    enabled: bool = True,
) -> User:
    """注册或覆盖用户；新注册接口默认 enabled=False。"""
    uid = str(uuid.uuid4())[:12]
    hashed = hash_password(password)
    project_ids = project_ids or []

    if is_configured():
        with get_db_session() as session:
            existing = session.scalar(select(UserModel).where(UserModel.username == username))
            if existing:
                existing.password_hash = hashed
                existing.role = role.value
                existing.enabled = enabled
                for pm in session.scalars(select(ProjectMemberModel).where(ProjectMemberModel.user_id == existing.id)).all():
                    session.delete(pm)
                for pid in project_ids:
                    if session.get(ProjectModel, pid) is None:
                        session.add(ProjectModel(id=pid, name=pid, slug=pid))
                    session.add(ProjectMemberModel(project_id=pid, user_id=existing.id, role="member"))
                session.flush()
                return User(id=existing.id, username=existing.username, role=Role(existing.role), project_ids=project_ids, enabled=existing.enabled)
            user = UserModel(id=uid, username=username, password_hash=hashed, role=role.value, enabled=enabled)
            session.add(user)
            for pid in project_ids:
                if session.get(ProjectModel, pid) is None:
                    session.add(ProjectModel(id=pid, name=pid, slug=pid))
                session.add(ProjectMemberModel(project_id=pid, user_id=uid, role="member"))
            session.flush()
            return User(id=uid, username=username, role=role, project_ids=project_ids, enabled=enabled)
    _users[uid] = {
        "id": uid,
        "username": username,
        "password_hash": hashed,
        "role": role.value,
        "project_ids": project_ids,
        "enabled": enabled,
    }
    _users_by_username[username] = uid
    return User(id=uid, username=username, role=role, project_ids=project_ids, enabled=enabled)


def get_user_by_username(username: str) -> Optional[dict]:
    if is_configured():
        with get_db_session() as session:
            row = session.scalar(select(UserModel).where(UserModel.username == username))
            if not row:
                return None
            pids = _get_project_ids_for_user(session, row.id)
            return {
                "id": row.id,
                "username": row.username,
                "password_hash": row.password_hash,
                "role": row.role,
                "project_ids": pids,
                "enabled": row.enabled,
            }
    uid = _users_by_username.get(username)
    if not uid:
        return None
    return _users.get(uid)


def get_user_by_id(user_id: str) -> Optional[User]:
    if is_configured():
        with get_db_session() as session:
            row = session.get(UserModel, user_id)
            if not row:
                return None
            pids = _get_project_ids_for_user(session, row.id)
            return User(id=row.id, username=row.username, role=Role(row.role), project_ids=pids, enabled=row.enabled)
    raw = _users.get(user_id)
    if not raw:
        return None
    return User(
        id=raw["id"],
        username=raw["username"],
        role=Role(raw["role"]),
        project_ids=raw.get("project_ids", []),
        enabled=raw.get("enabled", True),
    )


def authenticate_user(username: str, password: str) -> Optional[User]:
    raw = get_user_by_username(username)
    if not raw or not verify_password(password, raw["password_hash"]):
        return None
    if not raw.get("enabled", True):
        return None  # 账户已禁用
    return get_user_by_id(raw["id"])


async def get_current_user(
    authorization: Annotated[Optional[str], Header()] = None,
) -> User:
    """从 Authorization: Bearer <token> 解析并校验用户；未配置鉴权时可跳过。"""
    settings = get_settings()
    if settings.auth_disabled:
        return User(id="dev", username="dev", role=Role.admin, project_ids=[])
    if not authorization or not authorization.strip().lower().startswith("bearer "):
        raise NeoException(status_code=401, message="未提供认证信息", code=CODE_UNAUTHORIZED)
    token = authorization.strip()[7:].strip()
    payload = decode_jwt(token)
    if not payload or "sub" not in payload:
        raise NeoException(status_code=401, message="无效或过期的 Token", code=CODE_UNAUTHORIZED)
    user = get_user_by_id(payload["sub"])
    if not user:
        raise NeoException(status_code=401, message="用户不存在", code=CODE_UNAUTHORIZED)
    return user


def require_permission(permission: Permission):
    """依赖：要求当前用户具备某权限。返回可注入的依赖函数。"""

    async def _check(current_user: Annotated[User, Depends(get_current_user)]) -> User:
        if not current_user.has_permission(permission):
            raise NeoException(status_code=403, message="无此操作权限", code=CODE_FORBIDDEN)
        return current_user

    return _check


def ensure_case_access(current_user: User, case: Optional[dict]) -> None:
    """校验用户能否访问该案件；无权限抛 403。普通用户仅能访问自己创建的案件，管理员可访问项目下全部案件。"""
    if not case:
        return
    if not current_user.can_access_project(case.get("project_id", "")):
        raise NeoException(status_code=403, message="无此案件访问权限", code=CODE_FORBIDDEN)
    if current_user.role != Role.admin:
        created_by = case.get("created_by") or ""
        if created_by != current_user.id:
            raise NeoException(status_code=403, message="仅可访问自己创建的案件", code=CODE_FORBIDDEN)


def ensure_case_can_delete(current_user: User, case: Optional[dict]) -> None:
    """校验用户能否删除该案件：仅创建者或 admin；无权限抛 403。"""
    if not case:
        return
    ensure_case_access(current_user, case)
    if current_user.role == Role.admin:
        return
    created_by = case.get("created_by") or ""
    if created_by != current_user.id:
        raise NeoException(status_code=403, message="仅可删除自己创建的案件", code=CODE_FORBIDDEN)


def ensure_session_access(current_user: User, session: Optional[dict], get_case_fn) -> None:
    """校验用户能否访问该会话（通过 case 归属）。"""
    if not session:
        return
    case = get_case_fn(session.get("case_id", ""))
    ensure_case_access(current_user, case)


def list_users() -> list[dict]:
    """列出所有用户（供管理员）；返回 id, username, role, enabled。"""
    if is_configured():
        with get_db_session() as session:
            rows = session.scalars(select(UserModel)).all()
            return [{"id": r.id, "username": r.username, "role": r.role, "enabled": r.enabled} for r in rows]
    return [
        {"id": u["id"], "username": u["username"], "role": u["role"], "enabled": u.get("enabled", True)}
        for u in _users.values()
    ]


def update_user(
    user_id: str,
    *,
    enabled: Optional[bool] = None,
    role: Optional[Role] = None,
    password: Optional[str] = None,
) -> Optional[User]:
    """更新用户（管理员）；启用/禁用、角色、密码。"""
    if is_configured():
        with get_db_session() as session:
            row = session.get(UserModel, user_id)
            if not row:
                return None
            if enabled is not None:
                row.enabled = enabled
            if role is not None:
                row.role = role.value
            if password is not None:
                row.password_hash = hash_password(password)
        return get_user_by_id(user_id)
    raw = _users.get(user_id)
    if not raw:
        return None
    if enabled is not None:
        raw["enabled"] = enabled
    if role is not None:
        raw["role"] = role.value
    if password is not None:
        raw["password_hash"] = hash_password(password)
    return get_user_by_id(user_id)


# 初始化默认用户（admin / member）；始终确保存在且可登录
def _init_default_users() -> None:
    def _ensure(name: str, password: str, role: Role, project_ids: Optional[list[str]] = None) -> None:
        existing = get_user_by_username(name)
        if existing:
            if is_configured():
                register_user(name, password, role, project_ids=project_ids or [], enabled=True)
            else:
                uid = _users_by_username[name]
                _users[uid]["password_hash"] = hash_password(password)
                _users[uid]["enabled"] = True
                _users[uid]["role"] = role.value
                if project_ids is not None:
                    _users[uid]["project_ids"] = project_ids
        else:
            register_user(name, password, role, project_ids=project_ids, enabled=True)

    _ensure("admin", "admin123", Role.admin)
    _ensure("member", "member123", Role.member, project_ids=["proj1"])


# 未配置 DB 时在导入时初始化内存默认用户；配置 DB 时由 main.lifespan 在 init_db 后调用
if not is_configured():
    _init_default_users()
