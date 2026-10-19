/**
 * 案件列表页（我的案件）；按项目过滤，仅显示本人创建的案件；支持勾选批量删除。
 */
import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { listProjects, listCases, createCase, deleteCase, getMe } from '../api/client'
import { useDialog } from '../components/DialogProvider'
import type { Case } from '../api/types'
import styles from './CaseList.module.css'

export function CaseList() {
  const queryClient = useQueryClient()
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [batchDeleting, setBatchDeleting] = useState(false)

  const { data: me } = useQuery({ queryKey: ['me'], queryFn: () => getMe() })
  const { data: projectsData, isLoading: projectsLoading } = useQuery({
    queryKey: ['projects'],
    queryFn: () => listProjects(),
  })
  const projectId = projectsData?.items?.[0]?.id ?? ''
  const { data: casesData, isLoading: casesLoading } = useQuery({
    queryKey: ['cases', projectId],
    queryFn: () => listCases(projectId),
    enabled: !!projectId,
  })

  const createMutation = useMutation({
    mutationFn: (name: string) => createCase(projectId, name),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['cases', projectId] }),
  })

  const deleteMutation = useMutation({
    mutationFn: (caseId: string) => deleteCase(caseId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['cases', projectId] }),
  })

  const isLoading = projectsLoading || casesLoading
  const cases = casesData?.items ?? []
  const projectName = projectsData?.items?.[0]?.name ?? '默认项目'
  const userId = me?.user_id ?? ''
  const isAdmin = me?.role === 'admin'

  function canDelete(c: Case): boolean {
    return isAdmin || (c.created_by != null && c.created_by === userId)
  }

  const deletableCases = useMemo(() => cases.filter((c) => canDelete(c)), [cases, isAdmin, userId])
  const deletableIds = useMemo(() => new Set(deletableCases.map((c) => c.id)), [deletableCases])
  const allDeletableSelected =
    deletableIds.size > 0 && [...deletableIds].every((id) => selectedIds.has(id))

  function toggleSelect(id: string) {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  function toggleSelectAll() {
    if (allDeletableSelected) {
      setSelectedIds(new Set())
    } else {
      setSelectedIds(new Set(deletableIds))
    }
  }

  const { confirm, prompt } = useDialog()

  async function handleCreate() {
    const name = await prompt('请输入案件名称', '未命名案件', { title: '新建案件', confirmText: '创建' })
    if (name != null && name.trim()) createMutation.mutate(name.trim())
  }

  async function handleDelete(c: Case) {
    const ok = await confirm(`确定要删除案件「${c.name}」吗？其下所有会话将被一并删除。`, { danger: true })
    if (!ok) return
    deleteMutation.mutate(c.id)
  }

  async function handleBatchDelete() {
    if (selectedIds.size === 0) return
    const ok = await confirm(
      `确定要删除已选中的 ${selectedIds.size} 个案件吗？其下所有会话将被一并删除。`,
      { danger: true },
    )
    if (!ok) return
    setBatchDeleting(true)
    try {
      for (const id of selectedIds) {
        await deleteCase(id)
      }
      queryClient.invalidateQueries({ queryKey: ['cases', projectId] })
      setSelectedIds(new Set())
    } catch (e) {
      console.error(e)
      queryClient.invalidateQueries({ queryKey: ['cases', projectId] })
    } finally {
      setBatchDeleting(false)
    }
  }

  if (isLoading) {
    return (
      <div className={styles.page}>
        <h1 className={styles.title}>案件列表</h1>
        <p className={styles.loading}>加载中…</p>
      </div>
    )
  }

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <h1 className={styles.title}>案件列表</h1>
        <p className={styles.subtitle}>
          {projectsData?.items && projectsData.items.length > 1
            ? `项目：${projectName}，仅显示本人创建的案件`
            : '仅显示本人创建的案件'}
        </p>
        <button
          type="button"
          className={styles.primaryBtn}
          onClick={handleCreate}
          disabled={!projectId || createMutation.isPending}
        >
          {createMutation.isPending ? '创建中…' : '新建案件'}
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
      <div className={styles.tableWrap}>
        <table className={styles.table}>
          <thead>
            <tr>
              <th className={styles.checkboxCol}>
                {deletableCases.length > 0 && (
                  <input
                    type="checkbox"
                    checked={allDeletableSelected}
                    onChange={toggleSelectAll}
                    aria-label="全选可删除案件"
                  />
                )}
              </th>
              <th>名称</th>
              <th>案件 ID</th>
              <th>创建时间</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {cases.length === 0 ? (
              <tr>
                <td colSpan={5} className={styles.empty}>
                  暂无案件，请先创建案件或选择其他项目
                </td>
              </tr>
            ) : (
              cases.map((c) => (
                <tr key={c.id}>
                  <td className={styles.checkboxCol}>
                    {canDelete(c) ? (
                      <input
                        type="checkbox"
                        checked={selectedIds.has(c.id)}
                        onChange={() => toggleSelect(c.id)}
                        aria-label={`选择案件 ${c.name}`}
                      />
                    ) : null}
                  </td>
                  <td>
                    <Link to={`/cases/${c.id}/sessions`} className={styles.caseName}>
                      {c.name}
                    </Link>
                  </td>
                  <td className={styles.mono}>{c.id}</td>
                  <td className={styles.timeCell}>
                    {c.created_at ? new Date(c.created_at).toLocaleString('zh-CN') : '-'}
                  </td>
                  <td className={styles.actionsCell}>
                    <Link to={`/cases/${c.id}/sessions`} className={styles.link}>
                      进入会话
                    </Link>
                    {canDelete(c) && (
                      <button
                        type="button"
                        className={styles.deleteBtn}
                        onClick={() => handleDelete(c)}
                        disabled={deleteMutation.isPending}
                        title="删除案件（仅创建者或管理员）"
                      >
                        删除
                      </button>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
