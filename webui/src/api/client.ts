/**
 * API 客户端：带鉴权的请求封装，与后端 /api/v1 契约一致。
 */
import type {
  LoginBody,
  LoginResponse,
  MeResponse,
  RegisterBody,
  RegisterResponse,
  UserListItem,
  UserCasesResponse,
  ProjectListResponse,
  Case,
  CaseListResponse,
  Session,
  SessionListResponse,
  SessionStatusResponse,
  ChatMessagesResponse,
  SendChatResponse,
  EvidenceListResponse,
  UploadEvidenceResponse,
  PipelineListResponse,
  AuditListResponse,
  ApiErrorBody,
  WorkspaceListResponse,
  WorkspaceFileContentResponse,
  ChatMessageAgentPhase,
  NeoStreamEnvelope,
} from './types'
import { mapServerAgentPhasesToLive } from '../stream/streamChatReducer'
import type { StreamChatAction } from '../stream/streamChatReducer'

const API_BASE = import.meta.env.VITE_API_BASE ?? '/api/v1'

function getToken(): string | null {
  return localStorage.getItem('neo_token')
}

async function request<T>(
  path: string,
  options: RequestInit & { parseJson?: boolean } = {}
): Promise<T> {
  const { parseJson = true, ...init } = options
  const token = getToken()
  const headers: HeadersInit = {
    ...(init.headers as Record<string, string>),
  }
  if (token) headers['Authorization'] = `Bearer ${token}`

  const res = await fetch(`${API_BASE}${path}`, { ...init, headers })
  if (!res.ok) {
    let body: ApiErrorBody = {}
    try {
      body = (await res.json()) as ApiErrorBody
    } catch {
      body = { message: res.statusText }
    }
    const msg = body.message ?? body.detail ?? `HTTP ${res.status}`
    throw new Error(typeof msg === 'string' ? msg : JSON.stringify(msg))
  }
  if (parseJson) return res.json() as Promise<T>
  return res.text() as Promise<T>
}

// --- 健康检查（无鉴权） ---
export async function healthCheck(): Promise<{ status: string }> {
  const res = await fetch('/health')
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json() as Promise<{ status: string }>
}

// --- 认证 ---
export async function login(body: LoginBody): Promise<LoginResponse> {
  return request<LoginResponse>('/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}

export async function getMe(): Promise<MeResponse> {
  return request<MeResponse>('/auth/me')
}

export async function register(body: RegisterBody): Promise<RegisterResponse> {
  return request<RegisterResponse>('/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}

export async function listUsers(): Promise<UserListItem[]> {
  return request<UserListItem[]>('/auth/users')
}

export async function updateUser(
  userId: string,
  body: { enabled?: boolean; role?: string; password?: string }
): Promise<{ ok: boolean; user_id: string }> {
  return request(`/auth/users/${userId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}

export async function listUserCases(userId: string): Promise<UserCasesResponse> {
  return request<UserCasesResponse>(`/auth/users/${userId}/cases`)
}

// --- 项目 ---
export async function listProjects(): Promise<ProjectListResponse> {
  return request<ProjectListResponse>('/projects')
}

// --- 案件 ---
export async function listCases(projectId: string): Promise<CaseListResponse> {
  return request<CaseListResponse>(`/projects/${projectId}/cases`)
}

export async function createCase(projectId: string, name: string): Promise<Case> {
  return request<Case>(`/projects/${projectId}/cases`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
  })
}

export async function getCase(caseId: string): Promise<Case> {
  return request<Case>(`/cases/${caseId}`)
}

export async function deleteCase(caseId: string): Promise<{ ok: boolean; case_id: string }> {
  return request(`/cases/${caseId}`, { method: 'DELETE' })
}

// --- 会话 ---
export async function listSessions(caseId: string): Promise<SessionListResponse> {
  return request<SessionListResponse>(`/cases/${caseId}/sessions`)
}

export async function createSession(caseId: string): Promise<Session> {
  return request<Session>(`/cases/${caseId}/sessions`, { method: 'POST' })
}

export async function getSession(sessionId: string): Promise<Session> {
  return request<Session>(`/sessions/${sessionId}`)
}

export async function deleteSession(sessionId: string): Promise<{ ok: boolean; session_id: string }> {
  return request(`/sessions/${sessionId}`, { method: 'DELETE' })
}

export async function runPipeline(sessionId: string, pipelineId?: string): Promise<{ session_id: string; status: string; message: string }> {
  return request(`/sessions/${sessionId}/run`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ pipeline_id: pipelineId ?? 'single_host_quick' }),
  })
}

export async function getSessionStatus(sessionId: string): Promise<SessionStatusResponse> {
  return request<SessionStatusResponse>(`/sessions/${sessionId}/status`)
}

/** P1 HITL: 获取待审批的工具调用列表 */
export async function getPendingApprovals(sessionId: string): Promise<{ session_id: string; items: { approval_id: string; tool: string; args: Record<string, unknown> }[] }> {
  return request(`/sessions/${sessionId}/pending-approvals`)
}

/** P1 HITL: 批准工具调用 */
export async function approveTool(sessionId: string, tool: string, args: Record<string, unknown>): Promise<{ ok: boolean; approval_id?: string }> {
  return request(`/sessions/${sessionId}/approve-tool`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tool, args }),
  })
}

export async function getSessionAudit(sessionId: string): Promise<AuditListResponse> {
  return request<AuditListResponse>(`/sessions/${sessionId}/audit`)
}

export async function getSessionMessages(sessionId: string): Promise<ChatMessagesResponse> {
  return request<ChatMessagesResponse>(`/sessions/${sessionId}/messages`)
}

/** P2: 列出会话工作区文件 */
export async function listWorkspaceFiles(sessionId: string): Promise<WorkspaceListResponse> {
  return request<WorkspaceListResponse>(`/sessions/${sessionId}/workspace/files`)
}

/** P2: 读取工作区文件内容 */
export async function readWorkspaceFile(sessionId: string, filePath: string): Promise<WorkspaceFileContentResponse> {
  const encoded = filePath.split('/').map(encodeURIComponent).join('/')
  return request<WorkspaceFileContentResponse>(`/sessions/${sessionId}/workspace/files/${encoded}`)
}

/** 与后端 `skills_inject_mode` 一致：full=目录+正文；catalog_only=仅目录（正文靠 load_skill）。 */
export type SkillsInjectMode = 'full' | 'catalog_only'

/** 非流式：一次返回完整回复。evidenceIds 可选，传入时用于分析指定证据。 */
export async function sendChat(
  sessionId: string,
  content: string,
  options?: { evidenceIds?: string[]; skillsInjectMode?: SkillsInjectMode }
): Promise<SendChatResponse> {
  const body: {
    content: string
    stream: boolean
    evidence_ids?: string[]
    skills_inject_mode?: SkillsInjectMode
  } = { content, stream: false }
  if (options?.evidenceIds?.length) body.evidence_ids = options.evidenceIds
  if (options?.skillsInjectMode) body.skills_inject_mode = options.skillsInjectMode
  return request<SendChatResponse>(`/sessions/${sessionId}/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}

function parseStreamEnvelope(raw: string): NeoStreamEnvelope | null {
  try {
    const j = JSON.parse(raw) as NeoStreamEnvelope
    if (j.v !== 1 || typeof j.kind !== 'string' || typeof j.run_id !== 'string' || typeof j.seq !== 'number') {
      return null
    }
    const payload =
      j.payload && typeof j.payload === 'object' && !Array.isArray(j.payload)
        ? j.payload
        : {}
    return { ...j, payload: payload as Record<string, unknown> }
  } catch {
    return null
  }
}

/** 流式：SSE 统一信封（v1），通过 dispatch 驱动 streamChatReducer；每条 llm.delta 后 yield，避免同一次 read 内批处理导致不刷新。 */
export async function sendChatStream(
  sessionId: string,
  content: string,
  callbacks: { dispatch: (action: StreamChatAction) => void },
  options?: { evidenceIds?: string[]; skillsInjectMode?: SkillsInjectMode },
): Promise<{
  messageId: string
  fullContent: string
  serverAgentPhases?: ChatMessageAgentPhase[]
  active_skill_ids?: string[]
  skills_injection_digest?: string
  skills_inject_mode?: string
}> {
  const token = getToken()
  const body: {
    content: string
    stream: boolean
    evidence_ids?: string[]
    skills_inject_mode?: SkillsInjectMode
  } = { content, stream: true }
  if (options?.evidenceIds?.length) body.evidence_ids = options.evidenceIds
  if (options?.skillsInjectMode) body.skills_inject_mode = options.skillsInjectMode
  const res = await fetch(`${API_BASE}/sessions/${sessionId}/chat`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(body),
  })
  if (!res.ok) {
    const err = (await res.json().catch(() => ({}))) as ApiErrorBody
    const msg =
      (typeof err.message === 'string' ? err.message : null) ??
      (typeof err.detail === 'string' ? err.detail : err.detail != null ? JSON.stringify(err.detail) : null) ??
      String(res.status)
    throw new Error(msg)
  }
  const reader = res.body?.getReader()
  if (!reader) throw new Error('无响应体')
  const decoder = new TextDecoder()
  let buffer = ''
  let fullContent = ''
  let messageId = ''
  let serverAgentPhases: ChatMessageAgentPhase[] | undefined
  let active_skill_ids: string[] | undefined
  let skills_injection_digest: string | undefined
  let skills_inject_mode: string | undefined

  const processEnvelope = async (env: NeoStreamEnvelope): Promise<void> => {
    if (env.kind === 'llm.delta') {
      const agent = typeof env.payload.agent === 'string' ? env.payload.agent : ''
      const delta = typeof env.payload.content === 'string' ? env.payload.content : ''
      fullContent += delta
      const key = agent || 'unknown'
      callbacks.dispatch({ type: 'DELTA_BATCH', byAgent: { [key]: delta } })
      // 勿用 flushSync：在 React 19 + 异步 SSE 循环里易与并发渲染冲突，可能导致整段不更新或流中断。
      // 每条 delta 后让出一次微任务，使 React 有机会提交；同 tick 内多行 data 会逐条交错提交。
      await new Promise<void>((resolve) => queueMicrotask(resolve))
      return
    }
    callbacks.dispatch({ type: 'ENVELOPE', envelope: env })
    if (env.kind === 'run.completed') {
      const mid = env.payload.message_id
      if (typeof mid === 'string' && mid) messageId = mid
      const ap = env.payload.agent_phases
      if (Array.isArray(ap) && ap.length > 0) {
        serverAgentPhases = mapServerAgentPhasesToLive(ap)
      }
      const asi = env.payload.active_skill_ids
      if (Array.isArray(asi)) {
        active_skill_ids = asi.filter((x): x is string => typeof x === 'string' && x.length > 0)
      }
      const sid = env.payload.skills_injection_digest
      if (typeof sid === 'string') skills_injection_digest = sid
      const sim = env.payload.skills_inject_mode
      if (typeof sim === 'string') skills_inject_mode = sim
    }
    if (env.kind === 'run.failed') {
      const err = typeof env.payload.error === 'string' ? env.payload.error : ''
      if (err) fullContent += `\n\n（${err}）`
    }
  }

  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })
    const lines = buffer.split('\n')
    buffer = lines.pop() ?? ''
    for (const line of lines) {
      if (line.startsWith(':') || !line.trim()) continue
      if (line.startsWith('data: ')) {
        const raw = line.slice(6).trim()
        if (raw === '[DONE]') continue
        const env = parseStreamEnvelope(raw)
        if (env) await processEnvelope(env)
      }
    }
  }
  if (buffer.startsWith('data: ')) {
    const raw = buffer.slice(6).trim()
    const env = parseStreamEnvelope(raw)
    if (env) await processEnvelope(env)
  }
  return {
    messageId,
    fullContent: fullContent.trim() || '（无回复内容）',
    serverAgentPhases,
    active_skill_ids,
    skills_injection_digest,
    skills_inject_mode,
  }
}

// --- 证据 ---
export async function listEvidence(sessionId: string): Promise<EvidenceListResponse> {
  return request<EvidenceListResponse>(`/sessions/${sessionId}/evidence`)
}

export async function uploadEvidence(sessionId: string, file: File): Promise<UploadEvidenceResponse> {
  const form = new FormData()
  form.append('file', file)
  return request<UploadEvidenceResponse>(`/sessions/${sessionId}/evidence/upload`, {
    method: 'POST',
    body: form,
    headers: {},
  })
}

// --- 报告 ---
export interface Report {
  id: string
  session_id: string
  case_id: string
  title: string
  content: string
  evidence_refs?: unknown[]
  case_name?: string
  created_at?: string
  updated_at?: string
}

/** 生成报告（从历史聊天汇总） */
export async function generateReport(sessionId: string, title?: string): Promise<{ ok: boolean; report: Report }> {
  return request(`/sessions/${sessionId}/reports`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ title: title || '分析报告' }),
  })
}

/** 会话下的报告列表 */
export async function listSessionReports(sessionId: string): Promise<{ items: Report[]; total: number }> {
  const res = await request<{ session_id: string; items: Report[]; total: number }>(`/sessions/${sessionId}/reports`)
  return { items: res.items, total: res.total }
}

/** 我的报告（跨案件） */
export async function listMyReports(): Promise<{ items: Report[]; total: number }> {
  const res = await request<{ items: Report[]; total: number }>('/reports')
  return { items: res.items, total: res.total }
}

/** 获取单条报告（预览） */
export async function getReportDetail(sessionId: string, reportId: string): Promise<Report> {
  return request(`/sessions/${sessionId}/reports/${reportId}`)
}

/** 更新报告 */
export async function updateReport(sessionId: string, reportId: string, body: { title?: string; content?: string }): Promise<{ ok: boolean; report: Report }> {
  return request(`/sessions/${sessionId}/reports/${reportId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}

/** 删除报告 */
export async function deleteReport(sessionId: string, reportId: string): Promise<{ ok: boolean }> {
  return request(`/sessions/${sessionId}/reports/${reportId}`, { method: 'DELETE' })
}

/** 下载单条报告 */
export async function downloadReport(sessionId: string, reportId: string, format: 'md' | 'pdf'): Promise<void> {
  const token = getToken()
  const res = await fetch(`${API_BASE}/sessions/${sessionId}/reports/${reportId}/download?format=${format}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  })
  if (!res.ok) throw new Error(res.statusText)
  const blob = await res.blob()
  const disposition = res.headers.get('Content-Disposition')
  const match = disposition?.match(/filename="?([^";]+)"?/)
  const filename = match ? match[1] : `report.${format}`
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

/** 批量下载报告（ZIP） */
export async function batchDownloadReports(reportIds: string[], format: 'md' | 'pdf'): Promise<void> {
  const token = getToken()
  const res = await fetch(`${API_BASE}/reports/batch-download`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({ report_ids: reportIds, format }),
  })
  if (!res.ok) throw new Error(res.statusText)
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'reports.zip'
  a.click()
  URL.revokeObjectURL(url)
}

// --- 流水线 ---
export async function listPipelines(): Promise<PipelineListResponse> {
  return request<PipelineListResponse>('/pipelines')
}
