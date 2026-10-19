# Neo 后端

数字取证与事件响应多智能体 Agent 平台后端。基于 uv + FastAPI，默认大模型 Qwen3-4b。

## 开发

```bash
# 安装依赖（需先安装 uv）
uv sync

# 启动开发服务
uv run uvicorn src.main:app --reload --host 0.0.0.0 --port 8000
```

## 测试

```bash
# 安装开发依赖
uv sync --extra dev

# 运行全部测试
uv run pytest

# 运行指定模块
uv run pytest tests/test_health.py -v

# 查看覆盖率（需安装 pytest-cov）
uv run pytest --tb=short -q
```

测试使用内存存储（无需 PostgreSQL），`AUTH_DISABLED=true` 跳过 JWT 鉴权。
测试文件说明：

| 文件 | 覆盖范围 |
|---|---|
| `test_health.py` | 健康检查、请求 ID 中间件 |
| `test_auth.py` | 登录、注册、用户管理 |
| `test_cases.py` | 案件 CRUD |
| `test_sessions.py` | 会话 CRUD、消息、状态 |
| `test_evidence.py` | 证据上传、列表 |
| `test_reports.py` | 报告生成、列表、更新、删除、下载 |
| `test_agents.py` | 智能体注册表、流水线模板、Agent API |
| `test_evidence_tools.py` | MCP 证据工具：ingest、分类、读取、artifact |
| `test_graph.py` | LangGraph 图构建、路由逻辑、状态 reducer |

## 环境变量

见 `.env.example`，复制为 `.env` 后按需修改。
