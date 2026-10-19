"""案件工作区技能目录：workspace/{case_id}/skills/{pack_slug}/SKILL.md"""
from __future__ import annotations

import re
from pathlib import Path

from src.core.config import get_settings

_PACK_SLUG_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


def sanitize_skill_pack_slug(name: str) -> str | None:
    """仅允许字母数字、连字符、下划线，长度 1～64。"""
    s = (name or "").strip()
    if not s:
        return None
    s = re.sub(r"[^a-zA-Z0-9_-]", "_", s).strip("_")
    if not s or len(s) > 64:
        return None
    if not _PACK_SLUG_RE.match(s):
        return None
    return s


def case_skills_root(case_id: str) -> Path:
    cid = (case_id or "").strip() or "_unknown"
    return get_settings().workspace_root_dir() / cid / "skills"


def ensure_case_skills_root(case_id: str) -> Path:
    root = case_skills_root(case_id)
    root.mkdir(parents=True, exist_ok=True)
    return root
