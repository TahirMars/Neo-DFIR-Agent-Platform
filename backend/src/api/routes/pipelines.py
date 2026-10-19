"""
流水线模板配置（管理端，M2 对接 pipeline.templates，RBAC）。
"""
from typing import Annotated

from fastapi import APIRouter, Depends

from src.core.auth import require_permission
from src.models.user import Permission, User
from src.pipeline.templates import list_pipelines as load_pipelines

router = APIRouter(prefix="/pipelines", tags=["流水线模板"])


@router.get("")
def list_pipelines(current_user: Annotated[User, Depends(require_permission(Permission.pipeline_list))]):
    """可用流水线模板列表（M2）；RBAC。"""
    items = load_pipelines()
    return {"items": items, "total": len(items)}
