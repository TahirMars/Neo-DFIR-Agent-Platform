"""将命中技能拼接为 system prompt 后缀。"""
from __future__ import annotations

import logging
from typing import Any

from src.core.config import get_settings
from src.skills.registry import get_skill_registry
from src.skills.schema import SkillDocument

logger = logging.getLogger(__name__)

_NEO_AGENT_KEYS = frozenset({"forensic", "sample", "report", "general_chat"})


def _skill_targets_agent(doc: SkillDocument, for_agent: str | None) -> bool:
    if not for_agent:
        return True
    agent = for_agent.strip().lower()
    if agent not in _NEO_AGENT_KEYS:
        return True
    targets = doc.meta.neo_agents
    if targets is None:
        return True
    return agent in targets


def skills_injection_digest(skill_ids: list[str], total_injected_chars: int) -> str:
    return f"{','.join(skill_ids)}|{total_injected_chars}c"


def _effective_inject_mode(state: dict[str, Any]) -> str:
    raw = (state.get("skills_inject_mode") or "").strip().lower()
    if raw in ("full", "catalog_only"):
        return raw
    default = (get_settings().skills_default_inject_mode or "full").strip().lower()
    return default if default in ("full", "catalog_only") else "full"


def build_skills_system_suffix(state: dict[str, Any], *, for_agent: str | None = None) -> str:
    """
    根据 DFIRState.active_skill_ids 与 case_id 加载 SKILL，返回注入块。
    skills_inject_mode：full=目录+正文（受预算截断）；catalog_only=仅目录，正文请用 load_skill。
    for_agent：forensic / sample / report / general_chat；仅注入 frontmatter 中 neo_agents 未限制或包含该角色的技能。
    """
    settings = get_settings()
    if not settings.skills_enabled:
        return ""

    ids = list(state.get("active_skill_ids") or [])
    if not ids:
        return ""

    case_id = (state.get("case_id") or "").strip()
    reg = get_skill_registry()
    docs, unknown = reg.resolve_documents(ids, case_id)
    if unknown:
        logger.info("未知 skill_id（已忽略）: %s", unknown)

    if for_agent:
        docs = [d for d in docs if _skill_targets_agent(d, for_agent)]

    if not docs:
        return ""

    mode = _effective_inject_mode(state)
    max_desc = settings.skills_description_max_chars
    max_body_total = settings.skills_body_max_chars

    lines: list[str] = ["<已启用技能（Neo Skills）>"]

    lines.append("## 技能目录（本轮）")
    for d in docs:
        desc = (d.meta.description or "").strip()
        if len(desc) > max_desc:
            desc = desc[: max_desc - 1] + "…"
        lines.append(f"- **{d.meta.name}** (`{d.meta.id}`): {desc or '（无描述）'}")

    if mode == "catalog_only":
        lines.append(
            "\n**正文未嵌入系统提示（渐进式加载）。** 分析前请对需要的 `skill_id` 调用工具 **`load_skill(skill_id)`** 获取完整步骤与检查清单。\n"
            "</已启用技能（Neo Skills）>",
        )
        return "\n".join(lines)

    lines.append("\n## 技能正文\n")
    bodies: list[str] = []
    remaining = max_body_total
    for d in docs:
        body = (d.body_markdown or "").strip()
        if not body:
            continue
        header = f"### {d.meta.name} (`{d.meta.id}`)\n\n"
        chunk = header + body
        if len(chunk) <= remaining:
            bodies.append(chunk)
            remaining -= len(chunk)
        else:
            if remaining > 200:
                bodies.append(chunk[: remaining] + "\n\n…（技能正文因预算截断）")
            break

    lines.append("\n\n".join(bodies))
    lines.append("</已启用技能（Neo Skills）>")
    return "\n".join(lines)
