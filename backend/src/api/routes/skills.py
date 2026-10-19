"""
Neo Skills：内置与案件工作区技能列表（供前端勾选 skill_ids）。
"""
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from src.core.auth import ensure_case_access, require_permission
from src.core.exceptions import CODE_NOT_FOUND, NeoException
from src.models.user import Permission, User
from src.services.session_store import get_case as store_get_case
from src.skills.registry import get_skill_registry
from src.skills.routing_rules import clear_routing_rules_cache

router = APIRouter(prefix="/skills", tags=["Skills"])


@router.get("")
def list_skills(
    current_user: Annotated[User, Depends(require_permission(Permission.session_run))],
    case_id: Annotated[str | None, Query(description="若提供则合并 workspace/{case_id}/skills 下的技能")] = None,
):
    """返回可用技能元数据（id / name / description / source），不含正文。"""
    reg = get_skill_registry()
    by_id: dict[str, dict] = {}

    for m in reg.list_builtin_metas():
        by_id[m.id] = {
            "id": m.id,
            "name": m.name,
            "description": m.description,
            "source": m.source,
        }

    cid = (case_id or "").strip()
    if cid:
        case_row = store_get_case(cid)
        if not case_row:
            raise NeoException(status_code=404, message="案件不存在", code=CODE_NOT_FOUND)
        ensure_case_access(current_user, case_row)
        for doc in reg.load_case_skills(cid).values():
            m = doc.meta
            by_id[m.id] = {
                "id": m.id,
                "name": m.name,
                "description": m.description,
                "source": m.source,
            }

    items = sorted(by_id.values(), key=lambda x: x["id"])
    return {"skills": items, "total": len(items)}


@router.post("/routing/reload")
def reload_skill_routing_rules(
    current_user: Annotated[User, Depends(require_permission(Permission.user_manage))],
):
    """清空 YAML 路由规则缓存（修改 data/skills_routing.yaml 后可调用）。"""
    clear_routing_rules_cache()
    return {"ok": True}
