-- Neo 后端 PostgreSQL 建表脚本（与 src/db/models.py 对齐）
-- 使用方式：psql -U postgres -d neo -f scripts/init_schema.sql
-- 或：应用启动时配置 DATABASE_URL，由 init_db() 自动建表（推荐）

-- 用户
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(64) PRIMARY KEY,
    username VARCHAR(128) NOT NULL UNIQUE,
    password_hash VARCHAR(256) NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'member',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_users_username ON users(username);

-- 项目
CREATE TABLE IF NOT EXISTS projects (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(256) NOT NULL,
    slug VARCHAR(128),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 项目成员
CREATE TABLE IF NOT EXISTS project_members (
    project_id VARCHAR(64) NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(32) NOT NULL DEFAULT 'member',
    PRIMARY KEY (project_id, user_id)
);

-- 案件
CREATE TABLE IF NOT EXISTS cases (
    id VARCHAR(64) PRIMARY KEY,
    project_id VARCHAR(64) NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name VARCHAR(256) NOT NULL,
    meta JSONB,
    created_by VARCHAR(64),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_cases_project_id ON cases(project_id);
CREATE INDEX IF NOT EXISTS ix_cases_created_by ON cases(created_by);

-- 会话
CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(64) PRIMARY KEY,
    case_id VARCHAR(64) NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    pipeline_id VARCHAR(128),
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    meta JSONB,
    evidence_ids JSONB,
    report_artifact_id VARCHAR(64),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_sessions_case_id ON sessions(case_id);

-- 会话消息（LLM 对话历史）
CREATE TABLE IF NOT EXISTS session_messages (
    id VARCHAR(64) PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    role VARCHAR(32) NOT NULL,
    content TEXT NOT NULL,
    tool_calls JSONB,
    evidence_refs JSONB,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_session_messages_session_id ON session_messages(session_id);
CREATE INDEX IF NOT EXISTS ix_session_messages_created_at ON session_messages(created_at);

-- 审计日志
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    request_id VARCHAR(64),
    case_id VARCHAR(64),
    session_id VARCHAR(64),
    user_id VARCHAR(64),
    action VARCHAR(64),
    resource_type VARCHAR(64),
    resource_id VARCHAR(64),
    tool_name VARCHAR(128),
    input_summary TEXT,
    output_summary TEXT,
    metrics JSONB,
    errors JSONB,
    duration_ms INTEGER,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_audit_logs_request_id ON audit_logs(request_id);
CREATE INDEX IF NOT EXISTS ix_audit_logs_case_id ON audit_logs(case_id);
CREATE INDEX IF NOT EXISTS ix_audit_logs_session_id ON audit_logs(session_id);
CREATE INDEX IF NOT EXISTS ix_audit_logs_created_at ON audit_logs(created_at);
