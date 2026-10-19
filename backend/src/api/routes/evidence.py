"""
证据上传路由（走 Evidence MCP 策略，M1 实现，RBAC）。
上传先落暂存区，经 evidence.ingest 原子移入证据区；会话关联 evidence_id。
"""
import uuid
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, UploadFile

from src.api.deps import validate_session_id
from src.core.auth import ensure_session_access, require_permission
from src.core.config import get_settings
from src.core.exceptions import CODE_NOT_FOUND, NeoException
from src.tools.evidence.tools import evidence_ingest, get_evidence_manifest
from src.models.user import Permission, User
from src.services.session_store import add_evidence_to_session, get_case as store_get_case, get_session

router = APIRouter(tags=["证据"])


@router.post("/sessions/{session_id}/evidence/upload")
async def upload_evidence(
    session_id: Annotated[str, Depends(validate_session_id)],
    file: UploadFile,
    current_user: Annotated[User, Depends(require_permission(Permission.evidence_upload))],
):
    """证据包上传：暂存 → evidence.ingest → 会话关联 evidence_id；校验会话归属。"""
    sess = get_session(session_id)
    if not sess:
        raise NeoException(status_code=404, message="会话不存在", code=CODE_NOT_FOUND)
    ensure_session_access(current_user, sess, store_get_case)
    case_id = sess["case_id"]
    settings = get_settings()
    if file.filename and not file.filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="仅支持 .zip 证据包")
    staging_dir = Path(settings.evidence_staging_dir())
    staging_dir.mkdir(parents=True, exist_ok=True)
    staging_name = f"upload_{uuid.uuid4().hex[:12]}_{file.filename or 'evidence.zip'}"
    staging_path = staging_dir / staging_name
    try:
        size = 0
        with open(staging_path, "wb") as f:
            while chunk := await file.read(65536):
                size += len(chunk)
                if size > settings.upload_max_bytes:
                    staging_path.unlink(missing_ok=True)
                    raise NeoException(status_code=413, message="文件超过上传大小限制")
                f.write(chunk)
        original_name = (file.filename or "evidence.zip").strip() or "evidence.zip"
        envelope = evidence_ingest(case_id, session_id, str(staging_path.resolve()), original_filename=original_name)
    finally:
        staging_path.unlink(missing_ok=True)
    if not envelope.get("ok"):
        raise NeoException(status_code=400, message="; ".join(envelope.get("errors", ["ingest 失败"])))
    evidence_id = envelope["data"]["evidence_id"]
    manifest = envelope["data"]["manifest"]
    add_evidence_to_session(session_id, evidence_id)
    return {"evidence_id": evidence_id, "session_id": session_id, "manifest": manifest}


@router.get("/sessions/{session_id}/evidence")
def list_evidence(
    session_id: Annotated[str, Depends(validate_session_id)],
    current_user: Annotated[User, Depends(require_permission(Permission.case_read))],
):
    """会话下证据列表；校验会话归属。"""
    sess = get_session(session_id)
    if not sess:
        raise NeoException(status_code=404, message="会话不存在", code=CODE_NOT_FOUND)
    ensure_session_access(current_user, sess, store_get_case)
    items = []
    for eid in sess.get("evidence_ids", []):
        manifest = get_evidence_manifest(eid)
        items.append({"evidence_id": eid, "manifest": manifest or {}})
    return {"items": items, "total": len(items)}
