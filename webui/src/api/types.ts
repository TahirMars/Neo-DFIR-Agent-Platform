/**
 * 前端 API 类型（与后端 OpenAPI/契约一致）
 */

// --- 认证 ---
export interface LoginBody {
  username: string
  password: string
}

export interface LoginResponse {
  access_token: string
  token_type: string
  user_id: string
  username: string
  role: string
}

export interface MeResponse {
  user_id: string
  username: string
  role: string
  project_ids: string[]
  enabled?: boolean
}

export interface RegisterBody {
  username: string
  password: string
}

export interface RegisterResponse {
  user_id: string
  username: string
  message?: string
}

export interface UserListItem {
  id: string
  username: string
  role: string
  enabled: boolean
}

export interface UserCasesResponse {
  items: Case[]
  total: number
  username: string
}

// --- 项目 ---
export interface Project {
  id: string
  name: string
}

export interface ProjectListResponse {
  items: Project[]
  total: number
}

// --- 案件 ---
export interface Case {
  id: string
  project_id: string
  name: string
  created_at?: string
  created_by?: string
}

export interface CaseListResponse {
  items: Case[]
  total: number
}

// --- 会话消息（与 AI 对话） ---
export interface ToolCallItem {
  name: string
  args: Record<string, unknown>
  result: string | null
  status: 'completed' | 'error' | 'pending'
}

export interface ChatMessageAgentPhase {
  agent: string
  label: string
  icon: string
  status: 'running' | 'completed' | 'error'
  content: string
  start_time: number
  end_time?: number
  tool_calls?: ToolCallItem[]
}

export interface AgentResultItem {
  status: 'completed' | 'failed' | 'skipped'
  analysis?: string
  report?: string
  files_analyzed?: number
  error?: string
}

export interface ChatMessage {
  id: string
  role: 'user' | 'assistant'
  content: string
  created_at?: string
  metadata?: {
    agent_phases?: ChatMessageAgentPhase[]
    agent_results?: Record<string, AgentResultItem>
    /** 本轮注入/激活的技能（LangGraph 多智能体） */
    active_skill_ids?: string[]
    skills_injection_digest?: string
    skills_inject_mode?: string
  }
}

export interface ChatMessagesResponse {
  session_id: string
  items: ChatMessage[]
  total: number
}

export interface SendChatResponse {
  user_message: ChatMessage
  assistant_message: ChatMessage
  /** 非流式 LangGraph 时与 assistant_message.metadata 一致，便于兼容旧客户端 */
  active_skill_ids?: string[]
  skills_injection_digest?: string
  skills_inject_mode?: string
}

/** SSE 统一事件信封（与后端 stream_envelope.StreamKind 对齐） */
export type NeoStreamKind =
  | 'run.started'
  | 'run.completed'
  | 'run.failed'
  | 'graph.step'
  | 'agent.start'
  | 'agent.end'
  | 'llm.delta'
  | 'tool.calls'
  | 'hitl.required'
  | 'agent.error'

export interface NeoStreamEnvelope {
  v: number
  run_id: string
  seq: number
  ts: string
  kind: NeoStreamKind
  payload: Record<string, unknown>
}

// --- 会话 ---
export interface Session {
  id: string
  case_id: string
  evidence_ids: string[]
  status: 'pending' | 'running' | 'completed' | 'failed'
  report_artifact_id?: string
  created_at?: string
  updated_at?: string
}

export interface SessionListResponse {
  items: Session[]
  total: number
}

export interface SessionStatusResponse {
  session_id: string
  status: string
  progress: number
}

// --- 证据 ---
export interface EvidenceItem {
  evidence_id: string
  manifest: Record<string, unknown>
}

export interface EvidenceListResponse {
  items: EvidenceItem[]
  total: number
}

export interface UploadEvidenceResponse {
  evidence_id: string
  session_id: string
  manifest: Record<string, unknown>
}

// --- 报告 ---
export interface ReportJsonData {
  markdown?: string
  evidence_refs?: EvidenceRef[]
  [key: string]: unknown
}

export interface EvidenceRef {
  evidence_id: string
  path?: string
  snippet?: string
  [key: string]: unknown
}

export interface ReportJsonResponse {
  session_id: string
  format: 'json'
  data: ReportJsonData
}

// --- 流水线 ---
export interface Pipeline {
  id: string
  name?: string
  description?: string
}

export interface PipelineListResponse {
  items: Pipeline[]
  total: number
}

// --- 审计 ---
export interface AuditEntry {
  tool_name?: string
  case_id?: string
  session_id?: string
  request_id?: string
  result_ok?: boolean
  duration_ms?: number
  [key: string]: unknown
}

export interface AuditListResponse {
  session_id: string
  items: AuditEntry[]
  total: number
}

// --- P2 工作区 ---
export interface WorkspaceFileItem {
  path: string
  size: number
  is_dir: boolean
}

export interface WorkspaceListResponse {
  session_id: string
  items: WorkspaceFileItem[]
}

export interface WorkspaceFileContentResponse {
  path: string
  content: string
  truncated: boolean
}

// --- 错误 ---
export interface ApiErrorBody {
  code?: string
  message?: string
  detail?: string | unknown
}
