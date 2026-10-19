"""解析 SKILL.md：YAML frontmatter + Markdown 正文。"""
from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path

import yaml

from src.skills.schema import SkillDocument, SkillMeta

logger = logging.getLogger(__name__)

_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n(.*)$", re.DOTALL | re.MULTILINE)


def parse_skill_text(
    raw: str,
    *,
    skill_id_fallback: str,
    source: str,
    path_display: str = "",
) -> SkillDocument | None:
    """解析 SKILL.md 文本（上传校验与磁盘读取共用）。"""
    if len(raw) > 512 * 1024:
        logger.warning("SKILL 文本过大，跳过: %s", path_display or "(memory)")
        return None

    m = _FRONTMATTER_RE.match(raw.strip())
    if not m:
        logger.warning("SKILL 缺少 YAML frontmatter: %s", path_display or "(memory)")
        return None

    try:
        fm = yaml.safe_load(m.group(1)) or {}
    except yaml.YAMLError as e:
        logger.warning("SKILL frontmatter YAML 无效 %s: %s", path_display or "(memory)", e)
        return None

    if not isinstance(fm, dict):
        return None

    sid = str(fm.get("id") or skill_id_fallback).strip()
    name = str(fm.get("name") or sid).strip()
    desc = str(fm.get("description") or "").strip()
    if not sid or not name:
        return None

    na = fm.get("neo_agents")
    neo_agents: tuple[str, ...] | None = None
    if isinstance(na, list):
        tup = tuple(str(x).strip().lower() for x in na if str(x).strip())
        neo_agents = tup if tup else None

    body = m.group(2).lstrip("\n")
    ch = hashlib.sha256(body.encode("utf-8")).hexdigest()[:12]

    meta = SkillMeta(
        id=sid,
        name=name,
        description=desc,
        source=source,
        path=path_display or "",
        checksum=ch,
        neo_agents=neo_agents,
    )
    return SkillDocument(meta=meta, body_markdown=body)


def parse_skill_file(path: Path, *, skill_id_fallback: str, source: str) -> SkillDocument | None:
    """
    读取并解析单个 SKILL.md。

    Args:
        path: SKILL.md 文件路径
        skill_id_fallback: frontmatter 无 id 时使用（通常为父目录名）
        source: builtin | case
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as e:
        logger.warning("读取 SKILL 失败 %s: %s", path, e)
        return None

    doc = parse_skill_text(
        raw,
        skill_id_fallback=skill_id_fallback,
        source=source,
        path_display=str(path.resolve()),
    )
    return doc
