"""
技能路由规则（YAML）：按案件名称、用户消息、case.meta.tags 匹配并附加 skill_ids。

文件路径由 Settings.skills_routing_rules_path 指定；不存在或为空则视为无规则。
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from src.core.config import get_settings

logger = logging.getLogger(__name__)

_rules_cache: tuple[float, list[dict[str, Any]]] | None = None


def clear_routing_rules_cache() -> None:
    """测试或热加载后清空缓存。"""
    global _rules_cache
    _rules_cache = None


def _load_rules_list() -> list[dict[str, Any]]:
    global _rules_cache
    path_str = (get_settings().skills_routing_rules_path or "").strip()
    if not path_str:
        return []
    path = Path(path_str)
    if not path.is_file():
        return []
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return []
    if _rules_cache is not None and _rules_cache[0] == mtime:
        return _rules_cache[1]
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as e:
        logger.warning("读取 skills 路由规则失败 %s: %s", path, e)
        return []
    if not isinstance(data, dict):
        rules: list[dict[str, Any]] = []
    else:
        raw = data.get("rules")
        rules = raw if isinstance(raw, list) else []
    _rules_cache = (mtime, rules)
    return rules


def _rule_matches(match: dict[str, Any], case_name: str, case_meta: dict[str, Any], user_message: str) -> bool:
    if not match:
        return False
    cn = (case_name or "").lower()
    um = (user_message or "").lower()

    subs = match.get("case_name_substrings") or []
    if subs:
        if not any(str(s).lower() in cn for s in subs):
            return False

    usubs = match.get("user_message_substrings") or []
    if usubs:
        if not any(str(s).lower() in um for s in usubs):
            return False

    tags_req = match.get("case_meta_tags_any") or []
    if tags_req:
        ct = case_meta.get("tags") if isinstance(case_meta, dict) else None
        if not isinstance(ct, list):
            ct = []
        ctn = {str(t).lower() for t in ct}
        if not any(str(t).lower() in ctn for t in tags_req):
            return False

    return bool(subs or usubs or tags_req)


def match_rule_skill_ids(
    case_name: str,
    case_meta: dict[str, Any] | None,
    user_message: str,
) -> list[str]:
    """按 YAML 规则返回应自动挂载的 skill_id 列表（有序去重在 router 层）。"""
    if not get_settings().skills_routing_enabled:
        return []
    meta = case_meta if isinstance(case_meta, dict) else {}
    out: list[str] = []
    seen: set[str] = set()
    for rule in _load_rules_list():
        if not isinstance(rule, dict):
            continue
        m = rule.get("match")
        if not isinstance(m, dict):
            continue
        if not _rule_matches(m, case_name, meta, user_message):
            continue
        for sid in rule.get("skill_ids") or []:
            s = str(sid).strip()
            if not s or s in seen:
                continue
            seen.add(s)
            out.append(s)
    return out
