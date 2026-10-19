/**
 * 流水线选择器：下拉展示 pipeline_id、名称、描述，选择后可与「运行」一起触发。
 */
import { useQuery } from '@tanstack/react-query'
import { listPipelines } from '../api/client'
import type { Pipeline } from '../api/types'
import styles from './PipelineSelector.module.css'

interface PipelineSelectorProps {
  value: string
  onChange: (pipelineId: string) => void
  disabled?: boolean
  /** 紧凑模式：隐藏「流水线」标签，仅显示下拉框（用于窄栏布局） */
  compact?: boolean
}

export function PipelineSelector({ value, onChange, disabled, compact }: PipelineSelectorProps) {
  const { data, isLoading } = useQuery({
    queryKey: ['pipelines'],
    queryFn: () => listPipelines(),
  })

  const items = data?.items ?? []

  return (
    <div className={styles.wrap}>
      <label className={compact ? styles.labelCompact : styles.label}>
        {!compact && '流水线 '}
        <select
          className={styles.select}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          disabled={disabled || isLoading}
        >
          {isLoading ? (
            <option value="">加载中…</option>
          ) : items.length === 0 ? (
            <option value="single_host_quick">single_host_quick（默认）</option>
          ) : (
            items.map((p: Pipeline) => (
              <option key={p.id} value={p.id}>
                {p.name ?? p.id}
              </option>
            ))
          )}
        </select>
      </label>
    </div>
  )
}
