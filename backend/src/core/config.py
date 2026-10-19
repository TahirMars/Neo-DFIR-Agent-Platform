"""
配置加载（pydantic-settings）。
基础设施：证据/暂存/会话导出、样本工作区、数据库/缓存/对象存储占位、JWT。
"""
from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")
    api_v1_prefix: str = "/api/v1"

    # 证据存储（M1）
    evidence_storage_path: str = "./data/evidence"
    evidence_staging_path: str = "./data/staging"
    upload_max_bytes: int = 512 * 1024 * 1024  # 512MB
    zip_max_uncompressed_ratio: int = 100  # 解压比上限，防 Zip Bomb
    zip_max_single_file_bytes: int = 500 * 1024 * 1024  # 单文件最大 500MB
    session_temp_export_path: str = "./data/session_export"  # 废弃，迁移至 workspace
    workspace_root_path: str = "./data/workspace"  # 统一工作区，支持 case/session 层级

    # 样本分析工作区（2.8，与证据区分离）
    sample_workspace_path: str = "./data/sample_workspace"
    # 动态分析：可选 shell 命令（shlex 拆分），Neo 将证据内解析后的样本绝对路径追加为最后一参；stdout 须为 JSON
    sample_dynamic_subprocess: Optional[str] = None
    sample_dynamic_timeout_seconds: int = 600

    # 数据库与缓存（可选；未配置时使用内存）
    database_url: Optional[str] = None
    redis_url: Optional[str] = None

    # 对象存储（可选；未配置时使用本地路径）
    s3_endpoint_url: Optional[str] = None
    s3_bucket_evidence: Optional[str] = None
    s3_bucket_sample: Optional[str] = None

    # 认证与 JWT
    jwt_secret: str = "neo-dev-secret-change-in-production"
    jwt_algorithm: str = "HS256"
    jwt_expire_seconds: int = 86400  # 24h
    auth_disabled: bool = False  # 开发时可设为 True 跳过鉴权

    # LLM（Qwen3-4b 或兼容 API）；未配置时对话/Agent 使用占位或降级
    llm_model: str = "qwen3-4b"
    llm_api_base: Optional[str] = "https://dashscope.aliyuncs.com/compatible-mode/v1"
    llm_api_key: Optional[str] = ""
    llm_max_tokens: int = 16384
    llm_timeout_seconds: int = 60
    llm_timeout_agent_seconds: int = 180  # 子智能体（取证/样本）单次 LLM 超时，长任务用

    # 会话与多智能体上下文（API 历史截断、拼接预算、摘要触发阈值）
    session_memory_single_msg_max_chars: int = 4000  # 纳入 compact 前单条消息最大长度（与 runtime 记忆截断对齐）
    session_context_formatted_max_chars: int = 12_000  # format_session_memory_for_graph 输出上限
    composed_user_context_max_chars: int = 28_000  # compose_agent_user_context 总字符上限（约 7k tokens）
    context_memory_trigger_chars: int = 60_000  # 会话总字符超此值触发 LLM 摘要并卸盘
    context_memory_light_append_chars: int = 12_000  # 总字符在此与 trigger 之间时写入轻量全量快照（无 LLM）
    session_workspace_persistence_enabled: bool = True  # 是否写入 workspace 下会话快照与分析轮次记录
    session_run_artifact_max_chars_per_block: int = 24_000  # analysis_runs.md 中单块正文上限
    case_memory_auto_init_enabled: bool = True  # 创建案件或首次 load 时写入 .case_memory.md 模板

    # LangGraph（P3）：内存 checkpointer，便于同进程内断点续跑/HITL 等扩展；默认关闭
    # thread_id 使用 X-Request-Id / request.state.request_id，否则每轮自动生成 UUID
    langgraph_checkpoint_enabled: bool = False

    # Neo Skills（SKILL.md 注入子 Agent）
    skills_enabled: bool = True
    skills_description_max_chars: int = 320  # 目录中单条 description 上限
    skills_body_max_chars: int = 8000  # 本轮注入的正文总预算（不含目录块）
    skills_upload_max_bytes: int = 256 * 1024  # 单文件 SKILL.md 上传上限
    skills_routing_enabled: bool = True  # 是否应用 YAML 规则自动挂载技能
    skills_routing_rules_path: Optional[str] = "./data/skills_routing.yaml"  # 不存在则仅显式 skill_ids
    # F3：渐进式披露 full=系统提示含正文；catalog_only=仅目录 + load_skill 工具拉正文
    skills_default_inject_mode: str = "full"  # full | catalog_only
    skills_load_tool_enabled: bool = True  # 是否为子 Agent 注册 load_skill
    skills_load_skill_result_max_chars: int = 12_000  # load_skill 返回上限（再大走 eviction）
    # F3：可选 LLM 根据用户问题从技能目录中追加推荐 id（在 YAML/显式 skill_ids 之后）
    skills_llm_routing_enabled: bool = False
    skills_llm_routing_max_suggestions: int = 3
    skills_llm_routing_catalog_max_chars: int = 6000  # 写入路由提示的技能列表最大字符

    # 威胁情报（MCP TI）
    virustotal_api_key: Optional[str] = None  # 未配置时 TI 使用模拟数据
    ti_whitelist_path: Optional[str] = None  # 白名单文件路径，每行一个 IOC
    ti_cache_path: Optional[str] = None  # SQLite 缓存路径，未配置则仅内存缓存
    sangfor_cookie: Optional[str] = None  # 深信服 TI Cookie（可选）
    sangfor_csrf_token: Optional[str] = None  # 深信服 CSRF Token（可选）

    def evidence_storage_dir(self) -> Path:
        return Path(self.evidence_storage_path).resolve()

    def evidence_staging_dir(self) -> Path:
        return Path(self.evidence_staging_path).resolve()

    def session_export_dir(self) -> Path:
        return Path(self.session_temp_export_path).resolve()

    def workspace_root_dir(self) -> Path:
        """工作区根目录：workspace/{case_id}/sessions/{session_id}/"""
        return Path(self.workspace_root_path).resolve()

    def sample_workspace_dir(self) -> Path:
        return Path(self.sample_workspace_path).resolve()


def get_settings() -> Settings:
    return Settings()
