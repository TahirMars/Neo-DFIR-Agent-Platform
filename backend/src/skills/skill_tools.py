"""供子 Agent 使用的 Skills 相关 LangChain 工具。"""
from __future__ import annotations

import logging

from langchain_core.tools import tool

from src.core.config import get_settings
from src.skills.registry import get_skill_registry
from src.tools.result_eviction import evict_large_result

logger = logging.getLogger(__name__)


def make_load_skill_tool(case_id: str, session_id: str):
    """按需返回单个技能的完整 Markdown 正文（可卸载大结果到 workspace）。"""

    @tool
    def load_skill(skill_id: str) -> str:
        """加载指定 Neo Skill 的完整正文（流程、检查清单等）。
        当系统提示里本轮技能仅有「目录」而未嵌入全文时，或需要再次查看某技能细节时调用。

        Args:
            skill_id: 技能 id，与目录中的 `id` 一致（如 dfir-report-checklist）
        """
        if not get_settings().skills_enabled:
            return "Skills 功能已关闭。"
        cid = (case_id or "").strip()
        sid = (session_id or "").strip()
        sid_raw = (skill_id or "").strip()
        if not sid_raw:
            return "skill_id 不能为空"

        reg = get_skill_registry()
        docs, unknown = reg.resolve_documents([sid_raw], cid)
        if unknown or not docs:
            return f"未找到技能: {sid_raw}（请使用 GET /api/v1/skills 核对 id）"

        d = docs[0]
        max_c = get_settings().skills_load_skill_result_max_chars
        header = f"# {d.meta.name} (`{d.meta.id}`)\n\n"
        body = (d.body_markdown or "").strip()
        text = header + body
        if len(text) > max_c:
            text = text[:max_c] + "\n\n…（正文过长已截断，可调大 skills_load_skill_result_max_chars）"

        return evict_large_result(text, cid, sid, "load_skill")

    return load_skill
