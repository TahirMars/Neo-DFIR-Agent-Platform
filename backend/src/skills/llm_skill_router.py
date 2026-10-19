"""
可选：用 LLM 根据用户问题从技能目录中追加 skill_id（F3）。
失败或未配置 API 时返回空列表，不阻断主流程。
"""
from __future__ import annotations

import json
import logging
import re
from langchain_core.messages import HumanMessage, SystemMessage

from src.agents.llm import get_chat_model, message_to_text
from src.core.config import get_settings
from src.skills.registry import get_skill_registry
from src.skills.schema import SkillMeta

logger = logging.getLogger(__name__)

_JSON_FENCE = re.compile(r"```(?:json)?\s*([\s\S]*?)```", re.IGNORECASE)


def _parse_skill_ids_json(text: str) -> list[str]:
    text = (text or "").strip()
    m = _JSON_FENCE.search(text)
    if m:
        text = m.group(1).strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        arr = data.get("skill_ids") or data.get("ids")
        if not isinstance(arr, list):
            return []
        return [str(x).strip() for x in arr if str(x).strip()]
    if isinstance(data, list):
        return [str(x).strip() for x in data if str(x).strip()]
    return []


def _build_catalog_lines(metas: list[SkillMeta], max_chars: int) -> tuple[str, set[str]]:
    lines: list[str] = []
    valid: set[str] = set()
    for m in metas:
        line = f"- `{m.id}`: {m.name} — {(m.description or '')[:200]}"
        lines.append(line)
        valid.add(m.id)
    text = "\n".join(lines)
    if len(text) <= max_chars:
        return text, valid
    return text[:max_chars] + "\n…（目录已截断）", valid


async def llm_suggest_extra_skill_ids(
    user_message: str,
    case_id: str,
    already_active: list[str],
) -> list[str]:
    """返回建议追加的 skill_id（不包含 already_active 中已有的）。"""
    settings = get_settings()
    if not settings.skills_llm_routing_enabled:
        return []
    if not (settings.llm_api_key or "").strip():
        return []

    reg = get_skill_registry()
    metas = reg.list_all_metas_for_case(case_id)
    if not metas:
        return []

    catalog, valid_ids = _build_catalog_lines(metas, settings.skills_llm_routing_catalog_max_chars)
    skip = {x.strip() for x in already_active if x.strip()}

    sys = SystemMessage(
        content=(
            "你是 Neo DFIR 平台的技能路由助手。根据「用户当前问题」从下列技能中选最相关的若干项，"
            "仅输出 JSON 对象，格式严格为：{\"skill_ids\":[\"id1\",\"id2\"] }。"
            "若无相关技能，输出 {\"skill_ids\":[]}。"
            "禁止选择不在列表中的 id；不要重复用户已启用的技能（已在下方列出）。"
        ),
    )
    human = HumanMessage(
        content=(
            f"用户已启用（勿重复推荐）: {sorted(skip) or '（无）'}\n\n"
            f"可选技能目录：\n{catalog}\n\n"
            f"用户问题：\n{(user_message or '')[:4000]}"
        ),
    )

    try:
        model = get_chat_model(max_tokens=256, temperature=0.1)
        resp = await model.ainvoke([sys, human])
        raw = message_to_text(resp)
        picked = _parse_skill_ids_json(raw)
    except Exception as e:
        logger.warning("LLM 技能路由失败: %s", e)
        return []

    cap = max(1, settings.skills_llm_routing_max_suggestions)
    out: list[str] = []
    seen = set(skip)
    for sid in picked:
        if sid not in valid_ids or sid in seen:
            continue
        seen.add(sid)
        out.append(sid)
        if len(out) >= cap:
            break
    return out


async def merge_skill_ids_with_llm(
    base_ids: list[str],
    user_message: str,
    case_id: str,
) -> list[str]:
    extra = await llm_suggest_extra_skill_ids(user_message, case_id, base_ids)
    if not extra:
        return list(base_ids)
    seen = set()
    merged: list[str] = []
    for x in list(base_ids) + extra:
        s = (x or "").strip()
        if not s or s in seen:
            continue
        seen.add(s)
        merged.append(s)
    return merged
