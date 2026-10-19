"""
案件工作区技能：上传 / 列出 / 删除 workspace/{case_id}/skills/{pack_slug}/SKILL.md
"""
from __future__ import annotations

import shutil
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, UploadFile

from src.api.deps import validate_case_id
from src.core.auth import ensure_case_access, require_permission
from src.core.config import get_settings
from src.core.exceptions import CODE_NOT_FOUND, NeoException
from src.models.user import Permission, User
from src.services.session_store import get_case as store_get_case
from src.skills.parser import parse_skill_text
from src.skills.registry import get_skill_registry
from src.skills.storage import ensure_case_skills_root, sanitize_skill_pack_slug

router = APIRouter(prefix="/cases", tags=["案件技能"])


@router.get("/{case_id}/skills")
def list_case_skills(
    case_id: Annotated[str, Depends(validate_case_id)],
    current_user: Annotated[User, Depends(require_permission(Permission.case_read))],
):
    """列出本案工作区下的技能包（不含内置）。"""
    case = store_get_case(case_id)
    if not case:
        raise NeoException(status_code=404, message="案件不存在", code=CODE_NOT_FOUND)
    ensure_case_access(current_user, case)
    items = get_skill_registry().list_case_skill_packages(case_id)
    return {"skills": items, "total": len(items)}


@router.post("/{case_id}/skills/upload")
async def upload_case_skill(
    case_id: Annotated[str, Depends(validate_case_id)],
    current_user: Annotated[User, Depends(require_permission(Permission.case_write))],
    file: UploadFile = File(...),
    pack_slug: Annotated[str | None, Form()] = None,
):
    """上传 SKILL.md 到本案 skills 目录；pack_slug 可选，默认用 frontmatter 的 id（经 sanitize）。"""
    case = store_get_case(case_id)
    if not case:
        raise NeoException(status_code=404, message="案件不存在", code=CODE_NOT_FOUND)
    ensure_case_access(current_user, case)

    if not (file.filename or "").lower().endswith((".md", ".markdown")):
        raise NeoException(status_code=400, message="仅支持 .md / .markdown 的 SKILL 文件", code="invalid_input")

    max_b = get_settings().skills_upload_max_bytes
    raw_bytes = await file.read()
    if len(raw_bytes) > max_b:
        raise NeoException(status_code=413, message="SKILL 文件超过大小限制", code="payload_too_large")

    try:
        raw = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise NeoException(status_code=400, message="文件须为 UTF-8 编码", code="invalid_input")

    doc = parse_skill_text(raw, skill_id_fallback="upload", source="case", path_display="(upload)")
    if not doc:
        raise NeoException(status_code=400, message="SKILL 解析失败：请检查 YAML frontmatter 与正文", code="invalid_skill")

    slug_src = (pack_slug or "").strip() or doc.meta.id
    slug = sanitize_skill_pack_slug(slug_src)
    if not slug:
        raise NeoException(
            status_code=400,
            message="无效的 pack_slug：仅允许字母数字、连字符、下划线，长度 1～64",
            code="invalid_input",
        )

    root = ensure_case_skills_root(case_id).resolve()
    target_dir = (root / slug).resolve()
    try:
        target_dir.relative_to(root)
    except ValueError:
        raise NeoException(status_code=400, message="非法路径", code="invalid_input") from None
    target_dir.mkdir(parents=True, exist_ok=True)
    skill_path = target_dir / "SKILL.md"
    try:
        skill_path.write_text(raw, encoding="utf-8")
    except OSError as e:
        raise NeoException(status_code=500, message=f"写入失败: {e}", code="write_error") from e

    return {
        "ok": True,
        "pack_slug": slug,
        "skill_id": doc.meta.id,
        "name": doc.meta.name,
        "path": str(skill_path.resolve()),
    }


@router.delete("/{case_id}/skills/{pack_slug}")
def delete_case_skill(
    case_id: Annotated[str, Depends(validate_case_id)],
    pack_slug: str,
    current_user: Annotated[User, Depends(require_permission(Permission.case_write))],
):
    """删除本案下指定技能包目录。"""
    case = store_get_case(case_id)
    if not case:
        raise NeoException(status_code=404, message="案件不存在", code=CODE_NOT_FOUND)
    ensure_case_access(current_user, case)

    slug = sanitize_skill_pack_slug(pack_slug)
    if not slug or slug != pack_slug.strip():
        raise NeoException(status_code=400, message="无效的 pack_slug", code="invalid_input")

    root = ensure_case_skills_root(case_id).resolve()
    target = (root / slug).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        raise NeoException(status_code=400, message="非法路径", code="invalid_input") from None
    if not target.is_dir():
        raise NeoException(status_code=404, message="技能包不存在", code=CODE_NOT_FOUND)
    shutil.rmtree(target, ignore_errors=True)
    return {"ok": True, "pack_slug": slug}
