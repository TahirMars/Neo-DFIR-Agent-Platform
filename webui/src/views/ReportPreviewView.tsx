/**
 * 报告预览：支持 Mermaid 渲染、编辑、下载。
 */
import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getReportDetail, updateReport, downloadReport } from '../api/client'
import { getCase } from '../api/client'
import { MarkdownContent } from '../components/MarkdownContent'
import styles from './ReportPreviewView.module.css'

export function ReportPreviewView() {
  const { caseId, sessionId, reportId } = useParams<{ caseId: string; sessionId: string; reportId: string }>()
  const queryClient = useQueryClient()
  const [editing, setEditing] = useState(false)
  const [editContent, setEditContent] = useState('')
  const [editTitle, setEditTitle] = useState('')
  const [downloading, setDownloading] = useState<'pdf' | 'md' | null>(null)

  const { data: caseData } = useQuery({
    queryKey: ['case', caseId],
    queryFn: () => getCase(caseId!),
    enabled: !!caseId,
  })
  const { data: report, isLoading, error } = useQuery({
    queryKey: ['report', reportId],
    queryFn: () => getReportDetail(sessionId!, reportId!),
    enabled: !!sessionId && !!reportId,
  })

  const updateMutation = useMutation({
    mutationFn: (body: { title?: string; content?: string }) => updateReport(sessionId!, reportId!, body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['report', reportId] })
      queryClient.invalidateQueries({ queryKey: ['reports', sessionId] })
      queryClient.invalidateQueries({ queryKey: ['reports'] })
      setEditing(false)
    },
  })

  const caseDisplayName = (caseData?.name?.trim() || '未命名案件') as string
  const content = editing ? editContent : (report?.content ?? '')
  const title = editing ? editTitle : (report?.title ?? '报告')

  function startEdit() {
    setEditContent(report?.content ?? '')
    setEditTitle(report?.title ?? '')
    setEditing(true)
  }

  function saveEdit() {
    updateMutation.mutate({ title: editTitle, content: editContent })
  }

  function cancelEdit() {
    setEditing(false)
  }

  async function handleDownload(format: 'pdf' | 'md') {
    if (!sessionId || !reportId) return
    setDownloading(format)
    try {
      await downloadReport(sessionId, reportId, format)
    } catch (e) {
      alert(`下载失败：${e instanceof Error ? e.message : String(e)}`)
    } finally {
      setDownloading(null)
    }
  }

  if (isLoading || !report) {
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
        <Link to={`/cases/${caseId}/sessions/${sessionId}/reports`} className={styles.back}>← 返回报告列表</Link>
      </div>
    )
  }

  return (
    <div className={styles.page}>
      <header className={styles.toolbar}>
        <Link to={`/cases/${caseId}/sessions/${sessionId}/reports`} className={styles.back}>
          ← 返回报告列表
        </Link>
        <span className={styles.breadcrumb}>{caseDisplayName} / {report.title}</span>
        <div className={styles.actions}>
          {editing ? (
            <>
              <button type="button" className={styles.cancelBtn} onClick={cancelEdit}>取消</button>
              <button
                type="button"
                className={styles.saveBtn}
                onClick={saveEdit}
                disabled={updateMutation.isPending}
              >
                {updateMutation.isPending ? '保存中…' : '保存'}
              </button>
            </>
          ) : (
            <>
              <button type="button" className={styles.editBtn} onClick={startEdit}>编辑</button>
              <button
                type="button"
                className={styles.downloadBtn}
                onClick={() => handleDownload('md')}
                disabled={!!downloading}
              >
                {downloading === 'md' ? '下载中…' : '下载 MD'}
              </button>
              <button
                type="button"
                className={styles.downloadBtn}
                onClick={() => handleDownload('pdf')}
                disabled={!!downloading}
              >
                {downloading === 'pdf' ? '下载中…' : '下载 PDF'}
              </button>
            </>
          )}
        </div>
      </header>

      <article className={styles.article}>
        {editing ? (
          <div className={styles.editArea}>
            <input
              type="text"
              className={styles.titleInput}
              value={editTitle}
              onChange={(e) => setEditTitle(e.target.value)}
              placeholder="报告标题"
            />
            <textarea
              className={styles.contentTextarea}
              value={editContent}
              onChange={(e) => setEditContent(e.target.value)}
              placeholder="报告内容（Markdown）"
              rows={24}
            />
          </div>
        ) : (
          <>
            <h1 className={styles.reportTitle}>{title}</h1>
            <MarkdownContent content={content} className={styles.markdown} />
          </>
        )}
      </article>
    </div>
  )
}
