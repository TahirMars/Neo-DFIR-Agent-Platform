/**
 * 首页：欢迎文案、平台特点、主要功能、快捷入口（功能布局说明 §5.2.1）。
 */
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import styles from './Home.module.css'

const FEATURES = [
  {
    icon: '🔍',
    title: '智能日志分析',
    desc: '解析 CSV/日志文件，识别威胁指标，自动重建攻击链，支持攻击类型定性（APT、勒索、黑产等）',
  },
  {
    icon: '📊',
    title: '多智能体协作',
    desc: '主管、取证分析、样本分析、报告生成等多智能体协同工作，自动规划任务并生成溯源报告',
  },
  {
    icon: '📝',
    title: '溯源调查报告',
    desc: '自动生成结构化调查溯源报告，含攻击链分析、时间线、关联分析、处置建议等',
  },
  {
    icon: '🛡️',
    title: '事件响应指导',
    desc: '提供 APT/黑产攻击事件处置建议，工具介绍与操作说明，指导用户进行事件响应',
  },
]

const WORKFLOW_STEPS = [
  { step: 1, text: '创建案件并上传证据' },
  { step: 2, text: '与 DFIR 智能体对话分析' },
  { step: 3, text: '获取溯源报告与处置建议' },
]

export function Home() {
  const [health, setHealth] = useState<{ status: string } | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetch('/health')
      .then((r) => r.json())
      .then(setHealth)
      .catch((e) => setError(e.message))
  }, [])

  return (
    <div className={styles.page}>
      <div className={styles.hero}>
        <h1 className={styles.title}>Neo</h1>
        <p className={styles.subtitle}>数字取证与事件响应（DFIR）智能体平台</p>
        <p className={styles.tagline}>
          基于多智能体协作的 DFIR 分析平台，支持日志分析、威胁情报、样本分析、攻击链重建与溯源报告生成
        </p>
      </div>

      <section className={styles.features}>
        <h2 className={styles.sectionTitle}>平台特点</h2>
        <div className={styles.featureGrid}>
          {FEATURES.map((f) => (
            <div key={f.title} className={styles.featureCard}>
              <span className={styles.featureIcon}>{f.icon}</span>
              <h3 className={styles.featureTitle}>{f.title}</h3>
              <p className={styles.featureDesc}>{f.desc}</p>
            </div>
          ))}
        </div>
      </section>

      <section className={styles.workflow}>
        <h2 className={styles.sectionTitle}>使用流程</h2>
        <div className={styles.workflowSteps}>
          {WORKFLOW_STEPS.map(({ step, text }) => (
            <div key={step} className={styles.workflowStep}>
              <span className={styles.stepNum}>{step}</span>
              <span className={styles.stepText}>{text}</span>
            </div>
          ))}
        </div>
      </section>

      <div className={styles.quickLinks}>
        <h2 className={styles.quickTitle}>快捷入口</h2>
        <div className={styles.links}>
          <Link to="/cases" className={styles.secondaryLink}>
            新建案件
          </Link>
          <Link to="/reports" className={styles.secondaryLink}>
            我的报告
          </Link>
        </div>
      </div>

      <div className={styles.status}>
        {health && <p className={styles.health}>后端状态: <strong>{health.status}</strong></p>}
        {error && <p className={styles.healthError}>后端连接失败: {error}</p>}
      </div>
    </div>
  )
}
