"""
智能体公共类型定义。
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AgentType(str, Enum):
    """智能体类型标识。"""
    supervisor = "supervisor"
    forensic = "forensic"
    sample = "sample"
    report = "report"
    default = "default"


@dataclass
class AgentContext:
    """单次智能体调用的上下文。"""
    case_id: str = ""
    session_id: str = ""
    user_message: str = ""
    session_memory: list[dict[str, str]] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    context_summary: str = ""
    request_id: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentResult:
    """智能体执行结果。"""
    agent_type: str = ""
    explanation: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    iocs: list[dict[str, Any]] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    error: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_type": self.agent_type,
            "explanation": self.explanation,
            "findings": self.findings,
            "iocs": self.iocs,
            "timeline": self.timeline,
            "recommendations": self.recommendations,
            "error": self.error,
        }
