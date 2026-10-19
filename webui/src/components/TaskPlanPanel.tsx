/**
 * 智能体执行结果面板
 * 展示 Supervisor 各子智能体的 agent_results
 */
import type { AgentResultItem } from '../api/types'
import styles from './TaskPlanPanel.module.css'

interface AgentResultsPanelProps {
  results: Record<string, AgentResultItem>
}

const AGENT_LABELS: Record<string, string> = {
  forensic: '取证分析',
  sample: '样本分析',
  report: '报告生成',
  general_chat: 'DFIR专家',
}

const STATUS_LABELS: Record<string, string> = {
  completed: '已完成',
  failed: '失败',
  skipped: '已跳过',
}

export function AgentResultsPanel({ results }: AgentResultsPanelProps) {
  const entries = Object.entries(results)
  if (entries.length === 0) return null

  return (
    <section className={styles.panel}>
      <h3 className={styles.title}>智能体执行结果</h3>
      <ul className={styles.taskList}>
        {entries.map(([agent, item]) => (
          <li key={agent} className={styles.taskItem}>
            <span className={`${styles.statusDot} ${styles[`status_${item.status}`]}`} />
            <span className={styles.taskLabel}>
              {AGENT_LABELS[agent] ?? agent}
              <span className={styles.fileCount}>
                {' '}— {STATUS_LABELS[item.status] ?? item.status}
                {item.files_analyzed != null && ` (${item.files_analyzed} 个文件)`}
              </span>
            </span>
          </li>
        ))}
      </ul>
    </section>
  )
}
