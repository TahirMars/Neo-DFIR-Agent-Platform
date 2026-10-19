/**
 * 我的报告：跨案件、会话的报告管理（查看、删除、编辑）。
 */
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { listMyReports, deleteReport, batchDownloadReports } from '../api/client'
import { useDialog } from '../components/DialogProvider'
import type { Report } from '../api/client'
import styles from './MyReportsView.module.css'

export function MyReportsView() {
  const queryClient = useQueryClient()
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [downloadFormat, setDownloadFormat] = useState<'pdf' | 'md'>('pdf')
  const [downloading, setDownloading] = useState(false)
  const [batchDeleting, setBatchDeleting] = useState(false)

  const { data, isLoading, error } = useQuery({
    queryKey: ['reports'],
    queryFn: () => listMyReports(),
  })

  const deleteMutation = useMutation({
    mutationFn: ({ sessionId, reportId }: { sessionId: string; reportId: string }) =>
      deleteReport(sessionId, reportId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['reports'] })
    },
  })

  const reports: Report[] = data?.items ?? []

  function toggleSelect(id: string) {
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  function toggleSelectAll() {
    if (selected.size === reports.length) setSelected(new Set())
    else setSelected(new Set(reports.map((r) => r.id)))
  }

  async function handleBatchDownload() {
    if (selected.size === 0) return
    setDownloading(true)
    try {
      await batchDownloadReports(Array.from(selected), downloadFormat)
    } catch (e) {
      alert(`下载失败：${e instanceof Error ? e.message : String(e)}`)
    } finally {
      setDownloading(false)
    }
  }

  const { confirm } = useDialog()

  async function handleBatchDelete() {
    if (selected.size === 0) return
    const ok = await confirm(`确定要删除已选中的 ${selected.size} 个报告吗？此操作不可撤销。`, { danger: true })
    if (!ok) return
    setBatchDeleting(true)
    try {
      for (const rid of selected) {
        const r = reports.find((rpt) => rpt.id === rid)
        if (r) await deleteReport(r.session_id, r.id)
      }
      queryClient.invalidateQueries({ queryKey: ['reports'] })
      setSelected(new Set())
    } catch (e) {
      console.error(e)
      queryClient.invalidateQueries({ queryKey: ['reports'] })
    } finally {
      setBatchDeleting(false)
    }
  }

  if (isLoading) {
    return (
      <div className={styles.page}>
        <p className={styles.loading}>加载中…</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className={styles.page}>
        <p className={styles.error}>加载失败：{error instanceof Error ? error.message : '未知错误'}</p>
      </div>
    )
  }

  return (
    <div className={styles.page}>
      <header className={styles.header}>
        <h1 className={styles.title}>我的报告</h1>
        <p className={styles.subtitle}>跨案件、会话的报告统一管理</p>
        {reports.length > 0 && (
          <div className={styles.actions}>
            <label className={styles.formatLabel}>
              格式：
              <select value={downloadFormat} onChange={(e) => setDownloadFormat(e.target.value as 'pdf' | 'md')}>
                <option value="pdf">PDF</option>
                <option value="md">Markdown</option>
              </select>
            </label>
            <button
              type="button"
              className={styles.batchBtn}
              onClick={handleBatchDownload}
              disabled={selected.size === 0 || downloading}
            >
              {downloading ? '下载中…' : `批量下载 (${selected.size})`}
            </button>
            {selected.size > 0 && (
              <button
                type="button"
                className={styles.batchDeleteBtn}
                onClick={handleBatchDelete}
                disabled={batchDeleting}
              >
                {batchDeleting ? '删除中…' : `批量删除（${selected.size}）`}
              </button>
            )}
          </div>
        )}
      </header>

      <section className={styles.section}>
        {reports.length === 0 ? (
          <p className={styles.empty}>
            暂无报告。请进入会话后，点击「生成报告」。
          </p>
        ) : (
          <>
            <div className={styles.selectAll}>
              <label>
                <input type="checkbox" checked={selected.size === reports.length} onChange={toggleSelectAll} />
                全选
              </label>
            </div>
            <ul className={styles.list}>
              {reports.map((r) => (
                <li key={r.id} className={styles.item}>
                  <label className={styles.checkbox}>
                    <input
                      type="checkbox"
                      checked={selected.has(r.id)}
                      onChange={() => toggleSelect(r.id)}
                    />
                  </label>
                  <div className={styles.itemMain}>
                    <Link
                      to={`/cases/${r.case_id}/sessions/${r.session_id}/reports/${r.id}`}
                      className={styles.itemTitle}
                    >
                      {r.title}
                    </Link>
                    <span className={styles.itemMeta}>
                      <span className={styles.caseInfo}>案件：{r.case_name ?? '未命名'}（{r.case_id}）</span>
                      {r.created_at && (
                        <span className={styles.itemDate}> · {new Date(r.created_at).toLocaleString()}</span>
                      )}
                    </span>
                  </div>
                  <div className={styles.itemActions}>
                    <Link
                      to={`/cases/${r.case_id}/sessions/${r.session_id}/reports/${r.id}`}
                      className={styles.previewBtn}
                    >
                      预览
                    </Link>
                    <button
                      type="button"
                      className={styles.deleteBtn}
                      onClick={async () => {
                        const ok = await confirm('确定删除此报告？', { danger: true })
                        if (ok) deleteMutation.mutate({ sessionId: r.session_id, reportId: r.id })
                      }}
                      disabled={deleteMutation.isPending}
                    >
                      删除
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          </>
        )}
      </section>
    </div>
  )
}
