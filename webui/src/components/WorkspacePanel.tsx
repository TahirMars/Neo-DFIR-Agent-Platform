/**
 * P2: Agent 工作区文件系统面板
 * 展示会话工作区内的中间文件，支持查看、下载、语法高亮（Markdown 渲染）
 */
import { useState, useCallback } from 'react'
import { useQuery } from '@tanstack/react-query'
import { listWorkspaceFiles, readWorkspaceFile } from '../api/client'
import { MarkdownContent } from './MarkdownContent'
import type { WorkspaceFileItem } from '../api/types'
import styles from './WorkspacePanel.module.css'

interface WorkspacePanelProps {
  sessionId: string
  defaultOpen?: boolean
}

function isMarkdown(path: string): boolean {
  const ext = path.split('.').pop()?.toLowerCase() ?? ''
  return ext === 'md' || ext === 'markdown'
}

export function WorkspacePanel({ sessionId, defaultOpen = false }: WorkspacePanelProps) {
  const [open, setOpen] = useState(defaultOpen)
  const [selectedFile, setSelectedFile] = useState<string | null>(null)

  const { data: filesData, isLoading } = useQuery({
    queryKey: ['workspace', sessionId],
    queryFn: () => listWorkspaceFiles(sessionId),
    enabled: !!sessionId && open,
  })

  const { data: fileContent, isLoading: contentLoading } = useQuery({
    queryKey: ['workspace-file', sessionId, selectedFile],
    queryFn: () => readWorkspaceFile(sessionId, selectedFile!),
    enabled: !!sessionId && !!selectedFile,
  })

  const items: WorkspaceFileItem[] = filesData?.items ?? []

  const handleDownload = useCallback((path: string, content: string) => {
    const name = path.split('/').pop() ?? path
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = name
    a.click()
    URL.revokeObjectURL(url)
  }, [])

  return (
    <section className={styles.panel}>
      <button
        type="button"
        className={styles.header}
        onClick={() => setOpen(!open)}
        aria-expanded={open}
      >
        <span className={styles.title}>工作区文件</span>
        <span className={styles.chevron}>{open ? '\u25BC' : '\u25B6'}</span>
      </button>
      {open && (
        <div className={styles.body}>
          {isLoading ? (
            <p className={styles.empty}>加载中…</p>
          ) : items.length === 0 ? (
            <p className={styles.empty}>暂无工作区文件</p>
          ) : (
            <ul className={styles.fileList}>
              {items.map((f) => (
                <li key={f.path} className={styles.fileItem}>
                  <button
                    type="button"
                    className={`${styles.fileBtn} ${selectedFile === f.path ? styles.fileBtnActive : ''}`}
                    onClick={() => setSelectedFile(f.path)}
                  >
                    <span className={styles.fileIcon}>📄</span>
                    <span className={styles.filePath}>{f.path}</span>
                    <span className={styles.fileSize}>{f.size > 1024 ? `${(f.size / 1024).toFixed(1)}KB` : `${f.size}B`}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}

          {selectedFile && (
            <div className={styles.viewer}>
              <div className={styles.viewerHeader}>
                <span className={styles.viewerPath}>{selectedFile}</span>
                {fileContent && (
                  <button
                    type="button"
                    className={styles.downloadBtn}
                    onClick={() => handleDownload(selectedFile, fileContent.content)}
                  >
                    下载
                  </button>
                )}
              </div>
              <div className={styles.viewerBody}>
                {contentLoading ? (
                  <p className={styles.empty}>加载中…</p>
                ) : fileContent ? (
                  fileContent.content ? (
                    isMarkdown(selectedFile) ? (
                      <div className={styles.markdownWrap}>
                        <MarkdownContent content={fileContent.content} />
                      </div>
                    ) : (
                      <pre className={styles.codeBlock}>
                        <code>{fileContent.content}</code>
                      </pre>
                    )
                  ) : (
                    <p className={styles.empty}>文件为空</p>
                  )
                ) : null}
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  )
}
