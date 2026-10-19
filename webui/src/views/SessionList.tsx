/**
 * 会话列表页（某案件下）：会话项、新建会话、进入会话详情/报告；支持勾选批量删除。
 */
import { useState } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getCase, listSessions, createSession, deleteSession } from '../api/client'
import { useDialog } from '../components/DialogProvider'
import type { Session } from '../api/types'
import styles from './SessionList.module.css'

export function SessionList() {
  const { caseId } = useParams<{ caseId: string }>()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [creating, setCreating] = useState(false)
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [batchDeleting, setBatchDeleting] = useState(false)

  const { data: caseData, isLoading: caseLoading } = useQuery({
    queryKey: ['case', caseId],
    queryFn: () => getCase(caseId!),
    enabled: !!caseId,
  })
  const { data: sessionsData, isLoading: sessionsLoading } = useQuery({
    queryKey: ['sessions', caseId],
    queryFn: () => listSessions(caseId!),
    enabled: !!caseId,
  })

  const createMutation = useMutation({
    mutationFn: () => createSession(caseId!),
    onSuccess: (session: Session) => {
      queryClient.invalidateQueries({ queryKey: ['sessions', caseId] })
      setCreating(false)
      navigate(`/cases/${caseId}/sessions/${session.id}`)
    },
    onError: () => setCreating(false),
  })

  const isLoading = caseLoading || sessionsLoading
  const sessions = sessionsData?.items ?? []
  /** 案件展示名：空名称时显示「未命名案件」 */
  const caseDisplayName = (caseData?.name?.trim() || '未命名案件') as string

  const allSessionIds = sessions.map((s) => s.id)
  const allSelected = allSessionIds.length > 0 && allSessionIds.every((id) => selectedIds.has(id))

  function toggleSelect(id: string) {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  function toggleSelectAll() {
    if (allSelected) {
      setSelectedIds(new Set())
    } else {
      setSelectedIds(new Set(allSessionIds))
    }
  }

  const { confirm } = useDialog()

  async function handleBatchDelete() {
    if (selectedIds.size === 0) return
    const ok = await confirm(`确定要删除已选中的 ${selectedIds.size} 个会话吗？`, { danger: true })
    if (!ok) return
    setBatchDeleting(true)
    try {
      for (const id of selectedIds) {
        await deleteSession(id)
      }
      queryClient.invalidateQueries({ queryKey: ['sessions', caseId] })
      setSelectedIds(new Set())
    } catch (e) {
      console.error(e)
      queryClient.invalidateQueries({ queryKey: ['sessions', caseId] })
    } finally {
      setBatchDeleting(false)
    }
  }

  if (isLoading && !caseData) {
    return (
      <div className={styles.page}>
        <p className={styles.loading}>加载中…</p>
      </div>
    )
  }

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <Link to="/cases" className={styles.back}>
          ← 返回案件列表
        </Link>
        <h1 className={styles.title}>{caseDisplayName}</h1>
        <p className={styles.subtitle}>会话列表 · {caseId}</p>
      </div>
      <div className={styles.actions}>
        {sessions.length > 0 && (
          <label className={styles.selectAllLabel}>
            <input
              type="checkbox"
              checked={allSelected}
              onChange={toggleSelectAll}
              aria-label="全选会话"
            />
            全选
          </label>
        )}
        <button
          type="button"
          className={styles.primaryBtn}
          onClick={() => {
            setCreating(true)
            createMutation.mutate()
          }}
          disabled={creating || createMutation.isPending}
        >
          {creating || createMutation.isPending ? '创建中…' : '新建会话'}
        </button>
        {selectedIds.size > 0 && (
          <button
            type="button"
            className={styles.batchDeleteBtn}
            onClick={handleBatchDelete}
            disabled={batchDeleting}
          >
            {batchDeleting ? '删除中…' : `批量删除（${selectedIds.size}）`}
          </button>
        )}
      </div>
      <ul className={styles.sessionList}>
        {sessions.length === 0 ? (
          <li className={styles.empty}>暂无会话，点击「新建会话」创建</li>
        ) : (
          sessions.map((s) => (
            <li key={s.id} className={styles.sessionItem}>
              <div className={styles.checkboxCol}>
                <input
                  type="checkbox"
                  checked={selectedIds.has(s.id)}
                  onChange={() => toggleSelect(s.id)}
                  aria-label={`选择会话 ${s.id}`}
                />
              </div>
              <div className={styles.sessionInfo}>
                <span className={styles.sessionId}>{s.id}</span>
                <span className={styles.sessionStatus} data-status={s.status}>
                  {s.status}
                </span>
                <span className={styles.sessionMeta}>
                  证据数: {s.evidence_ids?.length ?? 0}
                </span>
                {s.created_at && (
                  <span className={styles.sessionTime}>
                    {new Date(s.created_at).toLocaleString('zh-CN')}
                  </span>
                )}
              </div>
              <div className={styles.sessionActions}>
                <Link to={`/cases/${caseId}/sessions/${s.id}`} className={styles.link}>
                  进入
                </Link>
                <Link to={`/cases/${caseId}/sessions/${s.id}/reports`} className={styles.link}>
                  报告
                </Link>
              </div>
            </li>
          ))
        )}
      </ul>
    </div>
  )
}
