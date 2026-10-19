/**
 * 登录页（参考 Neo_v1.0.0 样式：背景斜纹动画、Logo 图标+文字、登录/注册标签页）。
 */
import { useState } from 'react'
import { useNavigate, useLocation, useSearchParams } from 'react-router-dom'
import { login, register } from '../api/client'
import { setStoredToken } from '../stores/auth'
import styles from './Login.module.css'

type TabType = 'login' | 'register'

export function Login() {
  const [activeTab, setActiveTab] = useState<TabType>('login')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()
  const location = useLocation()
  const [searchParams] = useSearchParams()
  const from = (location.state as { from?: string } | null)?.from ?? searchParams.get('from') ?? '/'

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setSuccess(null)
    setLoading(true)
    try {
      const res = await login({ username, password })
      setStoredToken(res.access_token)
      navigate(from, { replace: true })
    } catch (err) {
      const msg = err instanceof Error ? err.message : '登录失败'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  async function handleRegister(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setSuccess(null)
    if (password !== confirmPassword) {
      setError('两次输入的密码不一致')
      return
    }
    setLoading(true)
    try {
      const res = await register({ username, password })
      setSuccess(`注册成功！账号 "${res.username}" 已创建，当前为禁用状态。请联系管理员激活后再登录。`)
      setUsername('')
      setPassword('')
      setConfirmPassword('')
      setTimeout(() => {
        setActiveTab('login')
        setSuccess(null)
      }, 4000)
    } catch (err) {
      setError(err instanceof Error ? err.message : '注册失败')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className={styles.pageContainer}>
      <div className={styles.background}>
        <div className={styles.bgPattern} />
      </div>
      <div className={styles.content}>
        <div className={styles.card}>
          <div className={styles.header}>
            <div className={styles.logo}>
              <img src="/logo_white.svg" alt="DFIR智能体平台" className={styles.logoIcon} />
            </div>
            <h1 className={styles.title}>数字取证与事件响应(DFIR)智能体</h1>
            <p className={styles.subtitle}>欢迎使用 Neo 智能体平台</p>
          </div>

          <div className={styles.tabs}>
            <button
              type="button"
              className={activeTab === 'login' ? `${styles.tab} ${styles.tabActive}` : styles.tab}
              onClick={() => { setActiveTab('login'); setError(null); setSuccess(null); }}
            >
              登录
            </button>
            <button
              type="button"
              className={activeTab === 'register' ? `${styles.tab} ${styles.tabActive}` : styles.tab}
              onClick={() => { setActiveTab('register'); setError(null); setSuccess(null); }}
            >
              注册
            </button>
          </div>

          {error && (
            <div className={styles.error}>
              <span className={styles.errorIcon}>⚠️</span>
              {error}
            </div>
          )}
          {success && (
            <div className={styles.success}>
              <span className={styles.successIcon}>✅</span>
              {success}
            </div>
          )}

          {activeTab === 'login' && (
            <form className={styles.form} onSubmit={handleLogin}>
              <label className={styles.label}>
                用户名
                <input
                  type="text"
                  className={styles.input}
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="请输入用户名"
                  autoComplete="username"
                  disabled={loading}
                  required
                />
              </label>
              <label className={styles.label}>
                密码
                <input
                  type="password"
                  className={styles.input}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="请输入密码"
                  autoComplete="current-password"
                  disabled={loading}
                  required
                />
              </label>
              <button type="submit" className={styles.submit} disabled={loading}>
                {loading ? '登录中…' : '登录'}
              </button>
              <p className={styles.hint}>请先注册用户，联系管理员激活账户后再登录。</p>
            </form>
          )}

          {activeTab === 'register' && (
            <form className={styles.form} onSubmit={handleRegister}>
              <label className={styles.label}>
                用户名
                <input
                  type="text"
                  className={styles.input}
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="3-32 个字符，字母数字下划线"
                  autoComplete="username"
                  disabled={loading}
                  required
                  minLength={3}
                  maxLength={32}
                />
              </label>
              <label className={styles.label}>
                密码
                <input
                  type="password"
                  className={styles.input}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="至少 8 个字符"
                  autoComplete="new-password"
                  disabled={loading}
                  required
                  minLength={8}
                />
              </label>
              <label className={styles.label}>
                确认密码
                <input
                  type="password"
                  className={styles.input}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="再次输入密码"
                  autoComplete="new-password"
                  disabled={loading}
                  required
                />
              </label>
              <button type="submit" className={styles.submit} disabled={loading}>
                {loading ? '注册中…' : '注册'}
              </button>
              <p className={styles.hint}>注册即表示您同意服务条款与隐私政策。</p>
            </form>
          )}
        </div>
        <footer className={styles.footer}>© 2026 Neo 智能体平台. All rights reserved.</footer>
      </div>
    </div>
  )
}
