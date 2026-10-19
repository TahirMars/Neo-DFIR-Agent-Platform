/**
 * 会话详情页：与 AI 对话聊天框（支持流式/非流式）、证据、流水线、报告。
 */
import { useState, useRef, useEffect, useCallback, useReducer, useMemo, useDeferredValue } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  getSession,
  getCase,
  listEvidence,
  runPipeline,
  getSessionMessages,
  sendChat,
  sendChatStream,
  approveTool,
  generateReport,
  type SkillsInjectMode,
} from '../api/client'
import { EvidenceUpload } from '../components/EvidenceUpload'
import { WorkspacePanel } from '../components/WorkspacePanel'
import { AgentResultsPanel } from '../components/TaskPlanPanel'
import { PipelineSelector } from '../components/PipelineSelector'
import { MarkdownContent } from '../components/MarkdownContent'
import { ToolCallBox } from '../components/ToolCallBox'
import type { ChatMessage, ChatMessageAgentPhase, AgentResultItem } from '../api/types'
import { STREAM_AGENT_META } from '../stream/agentMeta'
import {
  initialStreamChatState,
  selectStreamPhaseList,
  streamChatReducer,
} from '../stream/streamChatReducer'
import styles from './SessionDetail.module.css'

interface AgentPhase {
  agent: string
  label: string
  icon: string
  status: 'running' | 'completed' | 'error'
  content: string
  startTime: number
  endTime?: number
  tool_calls?: { name: string; args: Record<string, unknown>; result: string | null; status: string }[]
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`
  return `${(ms / 1000).toFixed(1)}s`
}

function graphNodeLabel(node: string): string {
  return STREAM_AGENT_META[node]?.label ?? node
}

/** 流式阶段正文：用 useDeferredValue 合并高频 delta，避免 ReactMarkdown 每字同步阻塞主线程 */
function LivePhaseMarkdown({ content }: { content: string }) {
  const deferred = useDeferredValue(content)
  return <MarkdownContent content={deferred} />
}

/** 助手消息下方：本轮注入/激活的技能（metadata 由后端持久化） */
function RoundSkillsLine({ meta }: { meta?: ChatMessage['metadata'] }) {
  const ids = meta?.active_skill_ids
  const digest = (meta?.skills_injection_digest ?? '').trim()
  const mode = (meta?.skills_inject_mode ?? '').trim()
  const hasIds = Array.isArray(ids) && ids.length > 0
  if (!hasIds && !digest && !mode) return null
  return (
    <div className={styles.roundSkills}>
      <span className={styles.roundSkillsLabel}>本轮技能</span>
      {hasIds && (
        <span className={styles.roundSkillsTags}>
          {ids!.map((id) => (
            <span key={id} className={styles.skillTag}>{id}</span>
          ))}
        </span>
      )}
      {mode ? <span className={styles.roundSkillsMeta}>模式 {mode}</span> : null}
      {digest ? (
        <span className={styles.roundSkillsMeta} title={digest}>
          摘要 {digest.length > 56 ? `${digest.slice(0, 56)}…` : digest}
        </span>
      ) : null}
    </div>
  )
}

function savedChatPhaseToAgentPhase(p: ChatMessageAgentPhase): AgentPhase {
  return {
    agent: p.agent,
    label: p.label || (STREAM_AGENT_META[p.agent]?.label ?? p.agent),
    icon: p.icon || (STREAM_AGENT_META[p.agent]?.icon ?? '\u{2699}\u{FE0F}'),
    status: p.status === 'error' ? 'error' : 'completed',
    content: p.content ?? '',
    startTime: (p.start_time ?? 0) * 1000,
    endTime: p.end_time ? p.end_time * 1000 : undefined,
    tool_calls: p.tool_calls,
  }
}

export function SessionDetail() {
  const { caseId, sessionId } = useParams<{ caseId: string; sessionId: string }>()
  const queryClient = useQueryClient()
  const [pipelineId, setPipelineId] = useState('single_host_quick')
  const [chatInput, setChatInput] = useState('')
  const [useStream, setUseStream] = useState(true)
  const [skillsInjectMode, setSkillsInjectMode] = useState<SkillsInjectMode>('full')
  const [streaming, setStreaming] = useState(false)
  const [pendingUserMsg, setPendingUserMsg] = useState<string | null>(null)

  const [streamState, dispatch] = useReducer(streamChatReducer, initialStreamChatState)
  const streamStateRef = useRef(streamState)
  streamStateRef.current = streamState

  const agentPhases = useMemo(() => selectStreamPhaseList(streamState), [streamState])

  /** 是否已有任一子智能体流式正文（用于「正在分析」与阶段面板展示） */
  const streamingLiveText = useMemo(
    () => selectStreamPhaseList(streamState).map((p) => p.content).join(''),
    [streamState],
  )

  const [expandedAgents, setExpandedAgents] = useState<Set<string>>(new Set())

  // 历史 phases：按 assistant 消息 ID 存储，流式结束后持久保留
  const [phaseByMsgId, setPhaseByMsgId] = useState<Record<string, AgentPhase[]>>({})
  const pendingPhasesRef = useRef<AgentPhase[] | null>(null)
  // 历史 phases 展开状态（按消息 ID / msgId:agent 组合键）
  const [historyExpanded, setHistoryExpanded] = useState<Set<string>>(new Set())
  const [historyAgentExpanded, setHistoryAgentExpanded] = useState<Set<string>>(new Set())
  const [agentResults, setAgentResults] = useState<Record<string, AgentResultItem>>({})

  const messagesEndRef = useRef<HTMLDivElement>(null)
  const messagesContainerRef = useRef<HTMLDivElement>(null)
  const scrollRafRef = useRef<number | null>(null)

  const { data: caseData } = useQuery({
    queryKey: ['case', caseId],
    queryFn: () => getCase(caseId!),
    enabled: !!caseId,
  })
  const { data: session, isLoading: sessionLoading } = useQuery({
    queryKey: ['session', sessionId],
    queryFn: () => getSession(sessionId!),
    enabled: !!sessionId,
    refetchInterval: (query) => {
      const s = query.state.data?.status
      return s === 'running' ? 3000 : false
    },
  })
  const { data: evidenceData } = useQuery({
    queryKey: ['evidence', sessionId],
    queryFn: () => listEvidence(sessionId!),
    enabled: !!sessionId,
  })
  const { data: messagesData } = useQuery({
    queryKey: ['messages', sessionId],
    queryFn: () => getSessionMessages(sessionId!),
    enabled: !!sessionId,
    refetchInterval: (query) => {
      const data = query.state.data as { items?: ChatMessage[] } | undefined
      const items = data?.items ?? []
      const last = items[items.length - 1]
      if (last?.role === 'user') return 2000
      return false
    },
  })

  const runMutation = useMutation({
    mutationFn: () => runPipeline(sessionId!, pipelineId),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['session', sessionId] }) },
  })
  const chatMutation = useMutation({
    mutationFn: (vars: { content: string; skillsInjectMode: SkillsInjectMode }) =>
      sendChat(sessionId!, vars.content, {
        evidenceIds: evidenceIds.length ? evidenceIds : undefined,
        skillsInjectMode: vars.skillsInjectMode,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['messages', sessionId] })
      queryClient.invalidateQueries({ queryKey: ['workspace', sessionId] })
      setChatInput('')
    },
  })
  const generateMutation = useMutation({
    mutationFn: () => generateReport(sessionId!),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['reports', sessionId] }) },
  })

  const caseDisplayName = (caseData?.name?.trim() || '未命名案件') as string
  const evidenceList = evidenceData?.items ?? []
  const evidenceIds = [
    ...new Set([...evidenceList.map((e) => e.evidence_id), ...(session?.evidence_ids ?? [])]),
  ].filter(Boolean)
  const status = session?.status ?? 'pending'
  const messagesFromApi: ChatMessage[] = messagesData?.items ?? []

  // 从 API 消息中恢复已持久化的 phases（页面首次加载 / 重新进入会话）
  // 同时处理流式结束后待绑定的 pendingPhasesRef
  useEffect(() => {
    const updates: Record<string, AgentPhase[]> = {}

    for (const msg of messagesFromApi) {
      if (msg.role !== 'assistant' || phaseByMsgId[msg.id]) continue
      const saved = msg.metadata?.agent_phases
      if (saved && saved.length > 0) {
        updates[msg.id] = saved.map((p: ChatMessageAgentPhase) => ({
          agent: p.agent,
          label: p.label || (STREAM_AGENT_META[p.agent]?.label ?? p.agent),
          icon: p.icon || (STREAM_AGENT_META[p.agent]?.icon ?? '\u{2699}\u{FE0F}'),
          status: p.status === 'error' ? ('error' as const) : ('completed' as const),
          content: p.content ?? '',
          startTime: (p.start_time ?? 0) * 1000,
          endTime: p.end_time ? p.end_time * 1000 : undefined,
          tool_calls: p.tool_calls,
        }))
      }
    }

    if (pendingPhasesRef.current && messagesFromApi.length > 0) {
      const last = messagesFromApi[messagesFromApi.length - 1]
      if (last.role === 'assistant' && !phaseByMsgId[last.id] && !updates[last.id]) {
        updates[last.id] = pendingPhasesRef.current
        pendingPhasesRef.current = null
      }
    }

    if (Object.keys(updates).length > 0) {
      setPhaseByMsgId(prev => ({ ...prev, ...updates }))
    }
  }, [messagesFromApi, phaseByMsgId])

  useEffect(() => {
    const last = messagesFromApi.filter(m => m.role === 'assistant').pop()
    const ar = last?.metadata?.agent_results
    if (ar && typeof ar === 'object' && Object.keys(ar).length > 0) {
      setAgentResults(ar)
    }
  }, [messagesFromApi])

  const lastApiMsg = messagesFromApi[messagesFromApi.length - 1]
  const pendingAlreadyStored = lastApiMsg?.role === 'user' && lastApiMsg?.content === pendingUserMsg
  const displayMessages: ChatMessage[] = [
    ...messagesFromApi,
    ...(pendingUserMsg && !pendingAlreadyStored ? [{ id: '_pending_user', role: 'user' as const, content: pendingUserMsg }] : []),
  ]

  const scrollToBottom = useCallback(() => {
    if (scrollRafRef.current) cancelAnimationFrame(scrollRafRef.current)
    scrollRafRef.current = requestAnimationFrame(() => {
      const el = messagesContainerRef.current
      if (el) el.scrollTop = el.scrollHeight
      scrollRafRef.current = null
    })
  }, [])

  useEffect(() => {
    scrollToBottom()
  }, [displayMessages.length, streaming, scrollToBottom])

  useEffect(() => {
    if (streaming && agentPhases.length > 0) scrollToBottom()
  }, [agentPhases, streaming, scrollToBottom])

  useEffect(() => {
    if (streaming && streamingLiveText.length > 0) scrollToBottom()
  }, [streaming, streamingLiveText, scrollToBottom])

  // 仅在本轮流式期间把 running 阶段加入 expanded；不要在 completed 时清空，
  // 否则与「流式正文展开」冲突，且会在结束前瞬间收起卡片。
  useEffect(() => {
    if (!streaming) return
    for (const p of agentPhases) {
      if (p.status === 'running') {
        setExpandedAgents((exp) => (exp.has(p.agent) ? exp : new Set([...exp, p.agent])))
      } else if (p.status === 'error') {
        setExpandedAgents((exp) => new Set([...exp, p.agent]))
      }
    }
  }, [agentPhases, streaming])

  const prevStatusRef = useRef<string | undefined>(undefined)
  useEffect(() => {
    const prev = prevStatusRef.current
    prevStatusRef.current = status
    if (prev === 'running' && status === 'completed' && sessionId) {
      queryClient.invalidateQueries({ queryKey: ['reports', sessionId] })
      queryClient.invalidateQueries({ queryKey: ['reports'] })
    }
  }, [status, sessionId, queryClient])

  const toggleExpand = useCallback((agent: string) => {
    setExpandedAgents(prev => { const n = new Set(prev); if (n.has(agent)) n.delete(agent); else n.add(agent); return n })
  }, [])

  const toggleHistoryExpand = useCallback((msgId: string) => {
    setHistoryExpanded(prev => { const n = new Set(prev); if (n.has(msgId)) n.delete(msgId); else n.add(msgId); return n })
  }, [])

  const toggleHistoryAgent = useCallback((key: string) => {
    setHistoryAgentExpanded(prev => { const n = new Set(prev); if (n.has(key)) n.delete(key); else n.add(key); return n })
  }, [])

  async function handleSendChat(e: React.FormEvent) {
    e.preventDefault()
    const content = chatInput.trim()
    if (!content || (chatMutation.isPending && !streaming)) return
    if (useStream) {
      setPendingUserMsg(content)
      setChatInput('')
      setStreaming(true)
      setExpandedAgents(new Set())
      dispatch({ type: 'RESET' })
      let streamResult: Awaited<ReturnType<typeof sendChatStream>> | null = null
      try {
        streamResult = await sendChatStream(
          sessionId!,
          content,
          { dispatch },
          {
            evidenceIds: evidenceIds.length ? evidenceIds : undefined,
            skillsInjectMode,
          },
        )
      } catch (err) {
        dispatch({
          type: 'REQUEST_FAILED',
          message: err instanceof Error ? err.message : String(err),
        })
      } finally {
        if (streamResult?.serverAgentPhases?.length) {
          pendingPhasesRef.current = streamResult.serverAgentPhases.map(savedChatPhaseToAgentPhase)
        } else {
          const live = selectStreamPhaseList(streamStateRef.current)
          if (live.length > 0) {
            pendingPhasesRef.current = live.map((p) => ({
              ...p,
              status: 'completed' as const,
              endTime: p.endTime ?? Date.now(),
            }))
          }
        }
        setPendingUserMsg(null)
        setStreaming(false)
        dispatch({ type: 'RESET' })
        setExpandedAgents(new Set())
        queryClient.invalidateQueries({ queryKey: ['messages', sessionId] })
        queryClient.invalidateQueries({ queryKey: ['workspace', sessionId] })
      }
      return
    }
    chatMutation.mutate({ content, skillsInjectMode })
  }

  if (sessionLoading && !session) {
    return <div className={styles.page}><p className={styles.loading}>加载中…</p></div>
  }

  const lastMsg = displayMessages[displayMessages.length - 1]
  const waitingForResponseAfterRefresh = !streaming && lastMsg?.role === 'user'

  async function handleApproveTool() {
    const pa = streamState.pendingApproval
    if (!sessionId || !pa) return
    try {
      await approveTool(sessionId, pa.tool, pa.args)
      dispatch({ type: 'CLEAR_HITL' })
      queryClient.invalidateQueries({ queryKey: ['messages', sessionId] })
      queryClient.invalidateQueries({ queryKey: ['workspace', sessionId] })
    } catch (err) {
      console.error('审批失败:', err)
    }
  }

  /** 渲染 phases 步骤条 + 卡片（复用于实时 / 历史）；子智能体流式正文仅在对应阶段卡片内展示。 */
  function renderPhases(
    phases: AgentPhase[],
    checkExpanded: (agent: string) => boolean,
    onToggle: (agent: string) => void,
    isLive: boolean,
  ) {
    return (
      <>
        <div className={styles.phaseStepper}>
          {phases.map((phase, i) => (
            <div key={phase.agent} className={styles.phaseStep}>
              {i > 0 && <div className={`${styles.stepConnector} ${phase.status === 'completed' || phase.status === 'running' || phase.status === 'error' ? styles.stepConnectorActive : ''}`} />}
              <div className={`${styles.stepDot} ${phase.status === 'running' ? styles.stepDotRunning : ''} ${phase.status === 'completed' ? styles.stepDotDone : ''} ${phase.status === 'error' ? styles.stepDotError : ''}`}>
                {phase.status === 'completed' ? '\u2713' : phase.status === 'error' ? '\u274C' : phase.icon}
              </div>
              <span className={`${styles.stepLabel} ${phase.status === 'running' ? styles.stepLabelActive : ''} ${phase.status === 'error' ? styles.stepLabelError : ''}`}>{phase.label}</span>
            </div>
          ))}
        </div>
        {phases.map((phase) => {
          const hasContent = phase.content.trim().length > 0
          const showTools = Boolean(phase.tool_calls && phase.tool_calls.length > 0)
          // 本轮流式：running 或已有字时保持展开（含刚转 completed、尚未卸载面板的一帧）
          const isExpanded =
            (isLive && (phase.status === 'running' || hasContent)) || checkExpanded(phase.agent)
          const duration = phase.endTime ? formatDuration(phase.endTime - phase.startTime) : null
          return (
            <div key={phase.agent} className={`${styles.phaseCard} ${phase.status === 'running' ? styles.phaseCardRunning : phase.status === 'error' ? styles.phaseCardError : styles.phaseCardDone}`}>
              <div className={styles.phaseCardHeader} onClick={() => (hasContent || phase.status === 'error') && onToggle(phase.agent)} role={(hasContent || phase.status === 'error') ? 'button' : undefined} tabIndex={(hasContent || phase.status === 'error') ? 0 : undefined}>
                <span className={styles.phaseIcon}>{phase.status === 'error' ? '\u274C' : phase.icon}</span>
                <span className={styles.phaseLabel}>{phase.label}</span>
                <span className={phase.status === 'running' ? styles.phaseBadgeRunning : phase.status === 'error' ? styles.phaseBadgeError : styles.phaseBadgeDone}>
                  {phase.status === 'running' ? '处理中…' : phase.status === 'error' ? '执行失败' : '完成'}
                </span>
                {duration && <span className={styles.phaseDuration}>{duration}</span>}
                {hasContent && <span className={styles.phaseExpand}>{isExpanded ? '\u25B2' : '\u25BC'}</span>}
              </div>
              {isExpanded && (hasContent || showTools) && (
                <div className={styles.phaseCardBody}>
                  {hasContent && (
                    <div className={styles.bubbleAiContent}>
                      {isLive && phase.status === 'running' ? (
                        <>
                          <LivePhaseMarkdown content={phase.content} />
                          <span className={styles.typingCursor} aria-hidden />
                        </>
                      ) : (
                        <MarkdownContent content={phase.content} />
                      )}
                    </div>
                  )}
                  {showTools && (
                    <div className={styles.toolCallsWrap}>
                      <h4 className={styles.toolCallsTitle}>工具调用</h4>
                      <div className={styles.toolCallsList}>
                        {phase.tool_calls!.map((tc, i) => (
                          <ToolCallBox key={i} toolCall={{ ...tc, status: (tc.status || 'completed') as 'completed' | 'error' | 'pending' }} />
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )
        })}
      </>
    )
  }

  return (
    <div className={styles.page}>
      <div className={styles.backRow}>
        <Link to={`/cases/${caseId}/sessions`} className={styles.back}>← 返回「{caseDisplayName}」会话列表</Link>
      </div>
      <div className={styles.middle}>
        <div className={styles.leftColumn}>
          <section className={styles.pipelineBlock}>
            <h2 className={styles.sectionTitle}>流水线</h2>
            <div className={styles.pipelineSelectorWrap}><PipelineSelector value={pipelineId} onChange={setPipelineId} compact /></div>
            <div className={styles.pipelineActions}>
              <button type="button" className={styles.primaryBtn} onClick={() => runMutation.mutate()} disabled={runMutation.isPending || status === 'running'}>
                {runMutation.isPending || status === 'running' ? '执行中…' : '运行'}
              </button>
              {runMutation.isSuccess && <span className={styles.success}>✓ 已提交</span>}
              {runMutation.isError && <span className={styles.error}>{runMutation.error?.message}</span>}
            </div>
          </section>
          <section className={styles.evidenceSection}>
            <h2 className={styles.sectionTitle}>证据</h2>
            <EvidenceUpload sessionId={sessionId!} />
            {evidenceList.length > 0 && (
              <ul className={styles.evidenceList}>
                {evidenceList.map((e) => (
                  <li key={e.evidence_id} className={styles.evidenceItem}>
                    <span className={styles.evidenceId}>{e.evidence_id}</span>
                    <span className={styles.manifest}>{Object.keys(e.manifest ?? {}).length} 项</span>
                  </li>
                ))}
              </ul>
            )}
          </section>
          <AgentResultsPanel results={agentResults} />
          <WorkspacePanel sessionId={sessionId!} />
          <section className={styles.reportBlock}>
            <h2 className={styles.sectionTitle}>报告</h2>
            <div className={styles.reportActions}>
              <button type="button" className={styles.reportBtn} onClick={() => generateMutation.mutate()} disabled={generateMutation.isPending}>
                {generateMutation.isPending ? '生成中…' : '生成'}
              </button>
              <Link to={`/cases/${caseId}/sessions/${sessionId}/reports`} className={styles.reportLink}>查看</Link>
            </div>
          </section>
        </div>
        <section className={styles.chatSection}>
          <div className={styles.chatSectionHeader}>
            <h2 className={styles.sectionTitle}>聊天框</h2>
            <div className={styles.chatSectionControls}>
              <label className={styles.streamToggle}>
                <input type="checkbox" checked={useStream} onChange={(e) => setUseStream(e.target.checked)} disabled={chatMutation.isPending || streaming} />
                <span>流式输出</span>
              </label>
              <label className={styles.skillsInjectLabel}>
                <span className={styles.skillsInjectLabelText}>技能注入</span>
                <select
                  className={styles.skillsInjectSelect}
                  value={skillsInjectMode}
                  onChange={(e) => setSkillsInjectMode(e.target.value as SkillsInjectMode)}
                  disabled={chatMutation.isPending || streaming}
                  title="完整：系统提示含技能目录与正文（受预算截断）。仅目录：只注入目录，正文由模型通过 load_skill 按需加载。"
                >
                  <option value="full">完整</option>
                  <option value="catalog_only">仅目录</option>
                </select>
              </label>
            </div>
          </div>
          <div className={styles.chatArea}>
            <div className={styles.messages} ref={messagesContainerRef}>
              {displayMessages.length === 0 && !streaming ? (
                <p className={styles.chatEmpty}>发送消息开始对话，AI 将引导您上传证据与运行流水线。</p>
              ) : (
                displayMessages.map((msg) => {
                  const savedPhases = msg.role === 'assistant' ? phaseByMsgId[msg.id] : undefined
                  const isHistOpen = historyExpanded.has(msg.id)
                  return (
                    <div key={msg.id} className={msg.role === 'user' ? styles.messageRowUser : styles.messageRowAi}>
                      <span className={msg.role === 'user' ? styles.avatarUser : styles.avatarAi}>
                        {msg.role === 'user' ? '我' : <img src="/dfir.svg" alt="AI" className={styles.avatarAiImg} />}
                      </span>
                      <div className={msg.role === 'user' ? styles.bubbleUser : styles.bubbleAi}>
                        {msg.id !== '_pending_user' && <span className={styles.bubbleCheck} title="已送达">✓</span>}

                        {/* 历史执行详情（可折叠） */}
                        {savedPhases && savedPhases.length > 0 && (
                          <div className={styles.historyPhasesWrap}>
                            <button type="button" className={styles.historyToggle} onClick={() => toggleHistoryExpand(msg.id)}>
                              <span className={styles.historyToggleIcon}>{isHistOpen ? '\u25BC' : '\u25B6'}</span>
                              <span>执行详情</span>
                              <span className={styles.historyToggleSummary}>
                                {savedPhases.map(p => `${p.icon}${p.label}`).join(' → ')}
                              </span>
                            </button>
                            {isHistOpen && (
                              <div className={styles.historyPhasesBody}>
                                {renderPhases(
                                  savedPhases,
                                  (agent) => historyAgentExpanded.has(`${msg.id}:${agent}`),
                                  (agent) => toggleHistoryAgent(`${msg.id}:${agent}`),
                                  false,
                                )}
                              </div>
                            )}
                          </div>
                        )}

                        {msg.role === 'assistant' ? (
                          <>
                            <div className={styles.bubbleAiContent}>
                              <MarkdownContent content={msg.content} />
                            </div>
                            <RoundSkillsLine meta={msg.metadata} />
                          </>
                        ) : (
                          <span>{msg.content}</span>
                        )}
                      </div>
                    </div>
                  )
                })
              )}

              {/* 流式/等待：单一助手行，避免「正在分析」与阶段面板各占一行、正文出现时再弹出新气泡 */}
              {(streaming || waitingForResponseAfterRefresh) && (
                <div className={styles.messageRowAi}>
                  <span className={styles.avatarAi}><img src="/dfir.svg" alt="AI" className={styles.avatarAiImg} /></span>
                  <div className={styles.streamingAssistantColumn}>
                    {streaming && streamState.graphStep && (
                      <div className={styles.graphStepBar} title={(streamState.graphStep.keys || []).join(', ')}>
                        <span className={styles.graphStepBadge}>图</span>
                        <span>{graphNodeLabel(streamState.graphStep.node)}</span>
                        {(streamState.graphStep.keys?.length ?? 0) > 0 && (
                          <span className={styles.graphStepKeysMuted}>
                            {streamState.graphStep.keys!.slice(0, 4).join(' · ')}
                            {streamState.graphStep.keys!.length > 4 ? '…' : ''}
                          </span>
                        )}
                      </div>
                    )}
                    {streaming && agentPhases.length > 0 && (
                      <div className={styles.agentPhasesPanel}>
                        {renderPhases(agentPhases, (a) => expandedAgents.has(a), toggleExpand, true)}
                      </div>
                    )}
                    {streaming && agentPhases.length === 0 && (
                      <div className={styles.aiThinkingBubble}>
                        <div className={styles.thinkingDots}><span /><span /><span /></div>
                        <span className={styles.thinkingText}>正在分析</span>
                      </div>
                    )}
                    {waitingForResponseAfterRefresh && (
                      <div className={styles.aiThinkingBubble}>
                        <div className={styles.thinkingDots}><span /><span /><span /></div>
                        <span className={styles.thinkingText}>正在处理您的请求，请稍候…</span>
                      </div>
                    )}
                  </div>
                </div>
              )}
              <div ref={messagesEndRef} />
            </div>
            {streamState.pendingApproval && (
              <div className={styles.approvalBanner}>
                <span className={styles.approvalText}>
                  {streamState.pendingApproval.tool === 'run_dynamic_analysis'
                    ? `动态分析需审批：${(streamState.pendingApproval.args as { sample_path?: string }).sample_path ?? '未知样本'}`
                    : `工具 ${streamState.pendingApproval.tool} 需审批`}
                </span>
                <div className={styles.approvalActions}>
                  <button type="button" className={styles.approvalBtn} onClick={handleApproveTool}>批准</button>
                  <button type="button" className={styles.approvalBtnSecondary} onClick={() => dispatch({ type: 'CLEAR_HITL' })}>取消</button>
                </div>
              </div>
            )}
            <form className={styles.chatForm} onSubmit={handleSendChat}>
              <span className={styles.chatAttach} title="附件" aria-hidden>📎</span>
              <input type="text" className={styles.chatInput} value={chatInput} onChange={(e) => setChatInput(e.target.value)} placeholder="问我一个问题" disabled={chatMutation.isPending || streaming} />
              <button type="submit" className={styles.chatSend} disabled={chatMutation.isPending || streaming || !chatInput.trim()}>
                {chatMutation.isPending || streaming ? '发送中…' : '发送'}
              </button>
            </form>
          </div>
        </section>
      </div>
      <footer className={styles.statusBar}>
        <span className={styles.statusBarMeta}>案件: {caseDisplayName}</span>
        <span>流水线状态: <strong>{status}</strong></span>
        {session?.updated_at && <span className={styles.statusBarMeta}>更新于 {new Date(session.updated_at).toLocaleString()}</span>}
      </footer>
    </div>
  )
}
