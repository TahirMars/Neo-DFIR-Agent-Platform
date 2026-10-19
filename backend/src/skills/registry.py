"""技能注册表：扫描内置目录与案件工作区 skills/*/SKILL.md。"""
from __future__ import annotations

import logging
from pathlib import Path
from src.skills.parser import parse_skill_file
from src.skills.schema import SkillDocument, SkillMeta
from src.skills.storage import case_skills_root

logger = logging.getLogger(__name__)

_BUILTIN_DIR = Path(__file__).resolve().parent / "builtin"


class SkillRegistry:
    """内存注册表；案件技能按 case_id 惰性合并。"""

    def __init__(self) -> None:
        self._builtin: dict[str, SkillDocument] = {}
        self._refresh_builtin()

    def _refresh_builtin(self) -> None:
        self._builtin.clear()
        root = _BUILTIN_DIR
        if not root.is_dir():
            return
        for skill_md in sorted(root.glob("*/SKILL.md")):
            fid = skill_md.parent.name
            doc = parse_skill_file(skill_md, skill_id_fallback=fid, source="builtin")
            if doc:
                self._builtin[doc.meta.id] = doc

    def list_builtin_metas(self) -> list[SkillMeta]:
        return [d.meta for d in sorted(self._builtin.values(), key=lambda x: x.meta.id)]

    def list_all_metas_for_case(self, case_id: str) -> list[SkillMeta]:
        """内置 + 本案工作区技能元数据（去重，case 覆盖同 id）。"""
        case_map = self.load_case_skills(case_id)
        merged: dict[str, SkillMeta] = {d.meta.id: d.meta for d in self._builtin.values()}
        for d in case_map.values():
            merged[d.meta.id] = d.meta
        return sorted(merged.values(), key=lambda m: m.id)

    def _case_skill_root(self, case_id: str) -> Path | None:
        cid = (case_id or "").strip()
        if not cid:
            return None
        p = case_skills_root(cid)
        return p if p.is_dir() else None

    def list_case_skill_packages(self, case_id: str) -> list[dict]:
        """案件工作区下各技能包（pack_slug + 元数据），不含正文。"""
        root = self._case_skill_root(case_id)
        if not root:
            return []
        out: list[dict] = []
        for skill_md in sorted(root.glob("*/SKILL.md")):
            pack = skill_md.parent.name
            doc = parse_skill_file(skill_md, skill_id_fallback=pack, source="case")
            if doc:
                out.append({
                    "pack_slug": pack,
                    "id": doc.meta.id,
                    "name": doc.meta.name,
                    "description": doc.meta.description,
                    "source": "case",
                })
        return out

    def load_case_skills(self, case_id: str) -> dict[str, SkillDocument]:
        out: dict[str, SkillDocument] = {}
        root = self._case_skill_root(case_id)
        if not root:
            return out
        for skill_md in sorted(root.glob("*/SKILL.md")):
            fid = skill_md.parent.name
            doc = parse_skill_file(skill_md, skill_id_fallback=fid, source="case")
            if doc:
                out[doc.meta.id] = doc
        return out

    def resolve_documents(
        self,
        skill_ids: list[str],
        case_id: str,
    ) -> tuple[list[SkillDocument], list[str]]:
        """
        按请求顺序解析技能；builtin 与 case 同名时 case 覆盖。
        返回 (documents, unknown_ids)。
        """
        case_map = self.load_case_skills(case_id)
        merged: dict[str, SkillDocument] = {**self._builtin, **case_map}
        docs: list[SkillDocument] = []
        unknown: list[str] = []
        seen: set[str] = set()
        for raw in skill_ids:
            sid = (raw or "").strip()
            if not sid or sid in seen:
                continue
            seen.add(sid)
            doc = merged.get(sid)
            if doc:
                docs.append(doc)
            else:
                unknown.append(sid)
        return docs, unknown

    def refresh(self) -> None:
        """热更新内置技能（开发调试用）。"""
        self._refresh_builtin()


_registry: SkillRegistry | None = None


def get_skill_registry() -> SkillRegistry:
    global _registry
    if _registry is None:
        _registry = SkillRegistry()
    return _registry
