/**
 * 流式对话事件归约（P0：统一信封 + reducer，与后端 StreamKind 对齐）。
 */
import type { ChatMessageAgentPhase, NeoStreamEnvelope, NeoStreamKind, ToolCallItem } from '../api/types'
import { STREAM_AGENT_META } from './agentMeta'

export interface StreamAgentPhase {
  agent: string
  label: string
  icon: string
  status: 'running' | 'completed' | 'error'
  content: string
  startTime: number
  endTime?: number
  tool_calls?: ToolCallItem[]
}

export interface StreamChatState {
  runId: string | null
  lastSeq: number
  phaseOrder: string[]
  phasesByAgent: Record<string, StreamAgentPhase>
  graphStep: { node: string; keys: string[] } | null
  pendingApproval: { approval_id: string; tool: string; args: Record<string, unknown> } | null
  runError: string | null
}

export const initialStreamChatState: StreamChatState = {
  runId: null,
  lastSeq: 0,
  phaseOrder: [],
  phasesByAgent: {},
  graphStep: null,
  pendingApproval: null,
  runError: null,
}

export type StreamChatAction =
  | { type: 'RESET' }
  | { type: 'ENVELOPE'; envelope: NeoStreamEnvelope }
  | { type: 'DELTA_BATCH'; byAgent: Record<string, string> }
  | { type: 'REQUEST_FAILED'; message: string }
  | { type: 'CLEAR_HITL' }

function metaFor(agent: string) {
  return STREAM_AGENT_META[agent] ?? { label: agent, icon: '\u{2699}\u{FE0F}' }
}

export function streamChatReducer(state: StreamChatState, action: StreamChatAction): StreamChatState {
  if (action.type === 'RESET') {
    return { ...initialStreamChatState }
  }

  if (action.type === 'CLEAR_HITL') {
    return { ...state, pendingApproval: null }
  }

  if (action.type === 'REQUEST_FAILED') {
    return {
      ...state,
      phaseOrder: ['error'],
      phasesByAgent: {
        error: {
          agent: 'error',
          label: '错误',
          icon: '\u{274C}',
          status: 'completed',
          content: `请求失败：${action.message}`,
          startTime: Date.now(),
        },
      },
    }
  }

  if (action.type === 'DELTA_BATCH') {
    const nextPhases = { ...state.phasesByAgent }
    const nextOrder = [...state.phaseOrder]
    for (const [agent, delta] of Object.entries(action.byAgent)) {
      if (!delta) continue
      let p = nextPhases[agent]
      if (!p) {
        const m = metaFor(agent)
        nextPhases[agent] = {
          agent,
          label: m.label,
          icon: m.icon,
          status: 'running',
          content: delta,
          startTime: Date.now(),
        }
        if (!nextOrder.includes(agent)) nextOrder.push(agent)
      } else {
        nextPhases[agent] = { ...p, content: p.content + delta }
      }
    }
    return { ...state, phasesByAgent: nextPhases, phaseOrder: nextOrder }
  }

  if (action.type !== 'ENVELOPE') return state

  const env = action.envelope
  const seq = Math.max(state.lastSeq, env.seq)
  const kind = env.kind as NeoStreamKind
  const p = env.payload || {}

  const base: StreamChatState = { ...state, lastSeq: seq }

  switch (kind) {
    case 'run.started':
      return { ...base, runId: env.run_id, runError: null }
    case 'graph.step': {
      const node = typeof p.node === 'string' ? p.node : ''
      const keys = Array.isArray(p.keys) ? (p.keys as string[]) : []
      return { ...base, graphStep: node ? { node, keys } : null }
    }
    case 'agent.start': {
      const agent = typeof p.agent === 'string' ? p.agent : ''
      if (!agent) return base
      const m = metaFor(agent)
      const phasesByAgent = { ...base.phasesByAgent }
      const phaseOrder = [...base.phaseOrder]
      if (!phasesByAgent[agent]) {
        phasesByAgent[agent] = {
          agent,
          label: m.label,
          icon: m.icon,
          status: 'running',
          content: '',
          startTime: Date.now(),
        }
        phaseOrder.push(agent)
      } else {
        phasesByAgent[agent] = { ...phasesByAgent[agent], status: 'running' }
      }
      return { ...base, phasesByAgent, phaseOrder }
    }
    case 'agent.end': {
      const agent = typeof p.agent === 'string' ? p.agent : ''
      if (!agent || !base.phasesByAgent[agent]) return base
      const cur = base.phasesByAgent[agent]
      if (cur.status === 'error') {
        return {
          ...base,
          phasesByAgent: {
            ...base.phasesByAgent,
            [agent]: { ...cur, endTime: cur.endTime ?? Date.now() },
          },
        }
      }
      return {
        ...base,
        phasesByAgent: {
          ...base.phasesByAgent,
          [agent]: {
            ...cur,
            status: 'completed',
            endTime: Date.now(),
          },
        },
      }
    }
    case 'agent.error': {
      const agent = typeof p.agent === 'string' ? p.agent : ''
      const message = typeof p.message === 'string' ? p.message : ''
      const errContent = `⚠️ 智能体执行失败：${message}\n\n请检查网络连接或稍后重试。`
      if (!agent) return { ...base, runError: message }
      const m = metaFor(agent)
      const phasesByAgent = { ...base.phasesByAgent }
      const phaseOrder = [...base.phaseOrder]
      const existing = phasesByAgent[agent]
      if (existing) {
        phasesByAgent[agent] = {
          ...existing,
          status: 'error',
          content:
            existing.content +
            (existing.content ? '\n\n' : '') +
            errContent,
          endTime: Date.now(),
        }
      } else {
        phasesByAgent[agent] = {
          agent,
          label: m.label,
          icon: m.icon,
          status: 'error',
          content: errContent,
          startTime: Date.now(),
          endTime: Date.now(),
        }
        phaseOrder.push(agent)
      }
      return { ...base, phasesByAgent, phaseOrder }
    }
    case 'tool.calls': {
      const agent = typeof p.agent === 'string' ? p.agent : ''
      const tool_calls = Array.isArray(p.tool_calls) ? (p.tool_calls as ToolCallItem[]) : []
      if (!agent || !tool_calls.length || !base.phasesByAgent[agent]) return base
      return {
        ...base,
        phasesByAgent: {
          ...base.phasesByAgent,
          [agent]: { ...base.phasesByAgent[agent], tool_calls },
        },
      }
    }
    case 'hitl.required':
      return {
        ...base,
        pendingApproval: {
          approval_id: typeof p.approval_id === 'string' ? p.approval_id : '',
          tool: typeof p.tool === 'string' ? p.tool : '',
          args: (p.args as Record<string, unknown>) ?? {},
        },
      }
    case 'run.completed':
      return { ...base, pendingApproval: null, graphStep: null }
    case 'run.failed': {
      const err = typeof p.error === 'string' ? p.error : '未知错误'
      return { ...base, runError: err, pendingApproval: null, graphStep: null }
    }
    default:
      return base
  }
}

export function selectStreamPhaseList(state: StreamChatState): StreamAgentPhase[] {
  return state.phaseOrder.map((a) => state.phasesByAgent[a]).filter(Boolean)
}

/** 将服务端 run.completed 中的 agent_phases 转为前端历史结构 */
export function mapServerAgentPhasesToLive(raw: unknown): ChatMessageAgentPhase[] {
  if (!Array.isArray(raw)) return []
  return raw.map((item) => {
    const o = item as Record<string, unknown>
    const agent = String(o.agent ?? '')
    const m = metaFor(agent)
    return {
      agent,
      label: typeof o.label === 'string' ? o.label : m.label,
      icon: typeof o.icon === 'string' ? o.icon : m.icon,
      status: o.status === 'error' ? 'error' : 'completed',
      content: typeof o.content === 'string' ? o.content : '',
      start_time: typeof o.start_time === 'number' ? o.start_time : 0,
      end_time: typeof o.end_time === 'number' ? o.end_time : undefined,
      tool_calls: Array.isArray(o.tool_calls) ? (o.tool_calls as ToolCallItem[]) : undefined,
    }
  })
}
