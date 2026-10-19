/**
 * 管理员查看指定用户的案件列表；可进入该用户的会话与报告。
 */
import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { listUserCases } from '../api/client'
import styles from './UserCasesView.module.css'

export function UserCasesView() {
  const { userId } = useParams<{ userId: string }>()

  const { data, isLoading, error } = useQuery({
    queryKey: ['userCases', userId],
    queryFn: () => listUserCases(userId!),
    enabled: !!userId,
  })

  if (isLoading) {
    return (
      <div className={styles.page}>
        <p className={styles.loading}>加载中…</p>
      </div>
    )
  }

  if (error || !data) {
    return (
      <div className={styles.page}>
        <p className={styles.error}>加载失败：{error instanceof Error ? error.message : '未知错误'}</p>
        <Link to="/cases" className={styles.back}>← 返回案件列表</Link>
      </div>
    )
  }

  const cases = data.items ?? []
  const username = data.username ?? userId ?? '—'

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <Link to="/cases" className={styles.back}>← 返回案件列表</Link>
        <h1 className={styles.title}>用户「{username}」的案件</h1>
        <p className={styles.subtitle}>管理员查看该用户创建的案件，可进入会话与报告</p>
      </div>
      <div className={styles.tableWrap}>
        <table className={styles.table}>
          <thead>
            <tr>
              <th>名称</th>
              <th>案件 ID</th>
              <th>项目 ID</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {cases.length === 0 ? (
              <tr>
                <td colSpan={4} className={styles.empty}>该用户暂无案件</td>
              </tr>
            ) : (
              cases.map((c) => (
                <tr key={c.id}>
                  <td>{c.name}</td>
                  <td className={styles.mono}>{c.id}</td>
                  <td className={styles.mono}>{c.project_id}</td>
                  <td>
                    <Link to={`/cases/${c.id}/sessions`} className={styles.link}>进入会话</Link>
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
