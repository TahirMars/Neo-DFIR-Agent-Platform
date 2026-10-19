"""
Agent 中间件：上下文管理、摘要压缩、案件记忆等。
"""
from src.agents.middleware.summarization import (
    compact_session_memory,
    DEFAULT_TRIGGER_CHARS,
    DEFAULT_KEEP_RECENT,
)
from src.agents.middleware.memory import (
    append_case_memory,
    ensure_case_memory_template_if_missing,
    load_case_memory,
    update_case_memory,
)

__all__ = [
    "compact_session_memory",
    "DEFAULT_TRIGGER_CHARS",
    "DEFAULT_KEEP_RECENT",
    "append_case_memory",
    "ensure_case_memory_template_if_missing",
    "load_case_memory",
    "update_case_memory",
]
