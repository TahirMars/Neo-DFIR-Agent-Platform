"""
Neo Skills 调用框架：内置/案件工作区 SKILL.md 解析、注册表、显式 skill_ids 注入子 Agent。
"""
from src.skills.injector import build_skills_system_suffix, skills_injection_digest
from src.skills.registry import SkillRegistry, get_skill_registry
from src.skills.router import resolve_active_skill_ids
from src.skills.schema import SkillDocument, SkillMeta

__all__ = [
    "SkillDocument",
    "SkillMeta",
    "SkillRegistry",
    "get_skill_registry",
    "build_skills_system_suffix",
    "skills_injection_digest",
    "resolve_active_skill_ids",
]
