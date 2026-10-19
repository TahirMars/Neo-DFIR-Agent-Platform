"""
智能体注册表：管理各类智能体的配置（提示词、参数等）。

v2: 保留配置查询能力，供 API 层展示智能体类型信息。
    实际 Agent 创建已迁移到各子 Agent 文件的工厂函数中。
"""
from typing import Any

from src.agents.common import AgentType
from src.agents.prompts import (
    DEFAULT_CHAT_PROMPT,
    FORENSIC_ANALYSIS_PROMPT,
    REPORT_GENERATION_PROMPT,
    SAMPLE_ANALYSIS_PROMPT,
    SUPERVISOR_SYSTEM_PROMPT,
)

_AGENT_CONFIGS: dict[str, dict[str, Any]] = {
    AgentType.supervisor: {
        "name": "主管智能体",
        "system_prompt": SUPERVISOR_SYSTEM_PROMPT,
        "description": "Supervisor：通过 tool-calling 动态编排子智能体（取证/样本/报告/对话）",
        "max_tokens": 16384,
    },
    AgentType.forensic: {
        "name": "取证分析智能体",
        "system_prompt": FORENSIC_ANALYSIS_PROMPT,
        "description": "日志与 IOC 分析：解析 CSV/日志、识别威胁、重建攻击链",
        "max_tokens": 16384,
    },
    AgentType.sample: {
        "name": "样本分析智能体",
        "system_prompt": SAMPLE_ANALYSIS_PROMPT,
        "description": "二进制样本静态分析：文件识别、特征提取、恶意行为推断",
        "max_tokens": 8192,
    },
    AgentType.report: {
        "name": "报告生成智能体",
        "system_prompt": REPORT_GENERATION_PROMPT,
        "description": "汇总所有分析结果，生成结构化溯源调查报告",
        "max_tokens": 16384,
    },
    AgentType.default: {
        "name": "DFIR 助手",
        "system_prompt": DEFAULT_CHAT_PROMPT,
        "description": "通用 DFIR 对话助手：问答、建议、威胁情报查询",
        "max_tokens": 16384,
    },
}


def list_agent_types() -> list[str]:
    return list(_AGENT_CONFIGS.keys())


def get_agent_config(agent_type: str) -> dict[str, Any]:
    return _AGENT_CONFIGS.get(agent_type, _AGENT_CONFIGS[AgentType.default])
