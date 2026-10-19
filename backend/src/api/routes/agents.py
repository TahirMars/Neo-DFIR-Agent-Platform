"""
Agent 类型配置（管理端，M2 对接 agents.registry，RBAC）。
"""
from typing import Annotated

from fastapi import APIRouter, Depends

from src.agents.registry import get_agent_config, list_agent_types
from src.core.auth import require_permission
from src.models.user import Permission, User

router = APIRouter(prefix="/agents", tags=["Agent 类型"])


@router.get("")
def list_agents(current_user: Annotated[User, Depends(require_permission(Permission.pipeline_list))]):
    """可用 Agent 类型列表（取证分析、样本分析、协同分析等）；RBAC。"""
    types = list_agent_types()
    items = []
    for t in types:
        cfg = get_agent_config(t)
        items.append({
            "agent_type": t,
            "name": cfg.get("name", t),
            "description": (cfg.get("system_prompt") or "")[:200],
        })
    return {"items": items, "total": len(items)}
