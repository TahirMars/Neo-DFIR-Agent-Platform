/**
 * P2: 工具调用详细展示
 * 可折叠的参数/结果，显示状态
 */
import { useState, useCallback } from 'react'
import type { ToolCallItem } from '../api/types'
import styles from './ToolCallBox.module.css'

interface ToolCallBoxProps {
  toolCall: ToolCallItem
}

export function ToolCallBox({ toolCall }: ToolCallBoxProps) {
  const [expanded, setExpanded] = useState(false)
  const [argsExpanded, setArgsExpanded] = useState<Record<string, boolean>>({})

  const { name, args, result, status } = toolCall
  const hasContent = result != null || (args && Object.keys(args).length > 0)

  const toggleArg = useCallback((key: string) => {
    setArgsExpanded(prev => ({ ...prev, [key]: !prev[key] }))
  }, [])

  const statusIcon = status === 'completed' ? '\u2713' : status === 'error' ? '\u274C' : '\u2699\uFE0F'

  return (
    <div className={styles.box}>
      <button
        type="button"
        className={styles.header}
        onClick={() => hasContent && setExpanded(!expanded)}
        disabled={!hasContent}
      >
        <span className={styles.statusIcon}>{statusIcon}</span>
        <span className={styles.name}>{name}</span>
        {hasContent && <span className={styles.chevron}>{expanded ? '\u25B2' : '\u25BC'}</span>}
      </button>
      {expanded && hasContent && (
        <div className={styles.body}>
          {args && Object.keys(args).length > 0 && (
            <div className={styles.section}>
              <h4 className={styles.sectionTitle}>参数</h4>
              {Object.entries(args).map(([key, value]) => (
                <div key={key} className={styles.argBlock}>
                  <button
                    type="button"
                    className={styles.argHeader}
                    onClick={() => toggleArg(key)}
                  >
                    <span className={styles.argKey}>{key}</span>
                    <span>{argsExpanded[key] ? '\u25B2' : '\u25BC'}</span>
                  </button>
                  {argsExpanded[key] && (
                    <pre className={styles.argValue}>
                      {typeof value === 'string' ? value : JSON.stringify(value, null, 2)}
                    </pre>
                  )}
                </div>
              ))}
            </div>
          )}
          {result != null && (
            <div className={styles.section}>
              <h4 className={styles.sectionTitle}>结果</h4>
              <pre className={styles.result}>
                {typeof result === 'string' ? result : JSON.stringify(result, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
