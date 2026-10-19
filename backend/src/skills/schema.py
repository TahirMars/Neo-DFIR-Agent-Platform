"""Skills 数据模型。"""
from dataclasses import dataclass, field


@dataclass(frozen=True)
class SkillMeta:
    """技能目录项（短描述，供路由与列表）。"""

    id: str
    name: str
    description: str
    source: str  # "builtin" | "case"
    path: str  # 绝对路径，便于调试
    checksum: str = ""  # 正文哈希简短形式，可选
    # None 表示注入所有子智能体；非空则仅 listed（小写）：forensic / sample / report / general_chat
    neo_agents: tuple[str, ...] | None = None


@dataclass
class SkillDocument:
    """解析后的 SKILL.md。"""

    meta: SkillMeta
    body_markdown: str
    resources: list[str] = field(default_factory=list)
