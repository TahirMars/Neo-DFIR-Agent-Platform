/**
 * 会话报告列表：勾选批量下载、点击预览。
 */
import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { listSessionReports, batchDownloadReports, deleteReport } from '../api/client'
import { getCase } from '../api/client'
import { useDialog } from '../components/DialogProvider'
import type { Report } from '../api/client'
import styles from './ReportListView.module.css'

export function ReportListView() {
  const { caseId, sessionId } = useParams<{ caseId: string; sessionId: string }>()
  const queryClient = useQueryClient()
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [downloadFormat, setDownloadFormat] = useState<'pdf' | 'md'>('pdf')
  const [downloading, setDownloading] = useState(false)

  const { data: caseData } = useQuery({
    queryKey: ['case', caseId],
    queryFn: () => getCase(caseId!),
    enabled: !!caseId,
  })
  const { data, isLoading, error } = useQuery({
    queryKey: ['reports', sessionId],
    queryFn: () => listSessionReports(sessionId!),
    enabled: !!sessionId,
  })

  const deleteMutation = useMutation({
    mutationFn: (reportId: string) => deleteReport(sessionId!, reportId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['reports', sessionId] })
      queryClient.invalidateQueries({ queryKey: ['reports'] })
    },
  })

  const { confirm } = useDialog()
  const caseDisplayName = (caseData?.name?.trim() || '未命名案件') as string
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
        <Link to={`/cases/${caseId}/sessions/${sessionId}`} className={styles.back}>← 返回会话详情</Link>
      </div>
    )
  }

  return (
    <div className={styles.page}>
      <header className={styles.toolbar}>
        <Link to={`/cases/${caseId}/sessions/${sessionId}`} className={styles.back}>
          ← 返回会话详情
        </Link>
        <div className={styles.actions}>
          {reports.length > 0 && (
            <>
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
            </>
          )}
        </div>
      </header>

      <section className={styles.section}>
        <h2 className={styles.title}>报告列表 · {caseDisplayName}</h2>
        {reports.length === 0 ? (
          <p className={styles.empty}>
            暂无报告。请返回会话详情后，点击「生成报告」。
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
                    <Link to={`/cases/${caseId}/sessions/${sessionId}/reports/${r.id}`} className={styles.itemTitle}>
                      {r.title}
                    </Link>
                    <span className={styles.itemMeta}>
                      {r.created_at ? new Date(r.created_at).toLocaleString() : ''}
                    </span>
                  </div>
                  <div className={styles.itemActions}>
                    <Link
                      to={`/cases/${caseId}/sessions/${sessionId}/reports/${r.id}`}
                      className={styles.previewBtn}
                    >
                      预览
                    </Link>
                    <button
                      type="button"
                      className={styles.deleteBtn}
                      onClick={async () => {
                        const ok = await confirm('确定删除此报告？', { danger: true })
                        if (ok) deleteMutation.mutate(r.id)
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
