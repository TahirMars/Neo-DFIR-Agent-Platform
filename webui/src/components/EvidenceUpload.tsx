/**
 * 证据上传：在会话上下文中上传 .zip 证据包，进度与结果反馈。
 */
import { useState, useRef } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { uploadEvidence } from '../api/client'
import styles from './EvidenceUpload.module.css'

interface EvidenceUploadProps {
  sessionId: string
}

export function EvidenceUpload({ sessionId }: EvidenceUploadProps) {
  const [error, setError] = useState<string | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const queryClient = useQueryClient()

  const mutation = useMutation({
    mutationFn: (file: File) => uploadEvidence(sessionId, file),
    onSuccess: () => {
      setError(null)
      queryClient.invalidateQueries({ queryKey: ['evidence', sessionId] })
      queryClient.invalidateQueries({ queryKey: ['session', sessionId] })
      inputRef.current?.form?.reset()
    },
    onError: (err: Error) => setError(err.message),
  })

  function handleChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return
    if (!file.name.toLowerCase().endsWith('.zip')) {
      setError('仅支持 .zip 证据包')
      return
    }
    setError(null)
    mutation.mutate(file)
  }

  return (
    <div className={styles.wrap}>
      <form
        onSubmit={(e) => e.preventDefault()}
        className={styles.form}
      >
        <label className={styles.label}>
          <span className={styles.labelText}>上传证据包（.zip）</span>
          <input
            ref={inputRef}
            type="file"
            accept=".zip"
            onChange={handleChange}
            disabled={mutation.isPending}
            className={styles.input}
          />
        </label>
        {mutation.isPending && <span className={styles.status}>上传中…</span>}
        {mutation.isSuccess && <span className={styles.success}>✓ 上传成功</span>}
      </form>
      {error && <div className={styles.error}>{error}</div>}
    </div>
  )
}
