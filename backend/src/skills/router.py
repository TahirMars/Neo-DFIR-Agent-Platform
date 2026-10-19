"""技能路由：YAML 规则 + API 显式 skill_ids 合并。"""
from __future__ import annotations

from src.core.config import get_settings
from src.skills.routing_rules import match_rule_skill_ids


def _normalize_explicit(requested: list[str] | None) -> list[str]:
    if not requested:
        return []
    seen: set[str] = set()
    out: list[str] = []
    for x in requested:
        s = (x or "").strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def resolve_active_skill_ids(
    requested: list[str] | None,
    case_id: str,
    *,
    case_name: str = "",
    case_meta: dict | None = None,
    user_message: str = "",
    apply_routing: bool = True,
) -> list[str]:
    """
    合并顺序：YAML 规则匹配的 skill_ids 在前，API 显式 skill_ids 在后；全局去重保序。
    """
    explicit = _normalize_explicit(requested)
    if not get_settings().skills_enabled:
        return explicit

    rule_ids: list[str] = []
    if apply_routing and (case_id or "").strip():
        rule_ids = match_rule_skill_ids(case_name, case_meta, user_message)

    seen: set[str] = set()
    out: list[str] = []
    for x in rule_ids + explicit:
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out
