/**
 * 主布局：侧边栏 + 顶栏面包屑 + 用户菜单（参考 功能布局说明）；管理员可打开用户管理。
 */
import { useState, useEffect, useRef } from 'react'
import { NavLink, Outlet, useLocation, useParams, Link } from 'react-router-dom'
import { getMe, getCase } from '../api/client'
import { clearStoredToken } from '../stores/auth'
import { getStoredTheme, setStoredTheme, applyTheme, type Theme } from '../stores/theme'
import { UserManagement } from './UserManagement'
import type { MeResponse } from '../api/types'
import styles from './Layout.module.css'

export function Layout() {
  const [user, setUser] = useState<MeResponse | null>(null)
  const [menuOpen, setMenuOpen] = useState(false)
  const [showUserManagement, setShowUserManagement] = useState(false)
  const [theme, setTheme] = useState<Theme>(() => getStoredTheme())
  const menuRef = useRef<HTMLDivElement>(null)
  const location = useLocation()
  const { caseId, sessionId } = useParams<{ caseId?: string; sessionId?: string }>()

  useEffect(() => {
    applyTheme(theme)
  }, [theme])

  useEffect(() => {
    getMe()
      .then(setUser)
      .catch(() => setUser(null))
  }, [])

  function toggleTheme() {
    const next: Theme = theme === 'dark' ? 'light' : 'dark'
    setTheme(next)
    setStoredTheme(next)
  }

  useEffect(() => {
    setMenuOpen(false)
  }, [location.pathname])

  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setMenuOpen(false)
    }
    if (menuOpen) {
      document.addEventListener('click', handleClickOutside)
      return () => document.removeEventListener('click', handleClickOutside)
    }
  }, [menuOpen])

  function handleLogout() {
    clearStoredToken()
    setUser(null)
    window.location.href = '/login'
  }

  const initial = user?.username ? user.username.charAt(0).toUpperCase() : '?'

  // 顶栏面包屑（按 功能布局说明 §4.1）
  const pathname = location.pathname.replace(/\/$/, '')
  const isReportsList = pathname.includes('/reports') && !pathname.match(/\/reports\/[^/]+$/)
  const isReportPreview = pathname.match(/\/reports\/[^/]+$/)
  const isMyReports = pathname === '/reports'
  const isSessionList = !!caseId && !sessionId && pathname.includes('/sessions')
  const isSessionDetail = !!caseId && !!sessionId && !isReportsList && !isReportPreview
  const isCases = pathname === '/cases'
  const isHome = pathname === ''

  const [caseName, setCaseName] = useState<string | null>(null)
  useEffect(() => {
    if (!caseId) {
      setCaseName(null)
      return
    }
    getCase(caseId)
      .then((c) => setCaseName(c.name))
      .catch(() => setCaseName(null))
  }, [caseId])

  /** 案件展示名：空名称时显示「未命名案件」 */
  const caseDisplayName = caseId && (caseName?.trim() ? caseName.trim() : '未命名案件')

  const breadcrumb = (
    <nav className={styles.breadcrumb} aria-label="面包屑">
      {isHome && <span className={styles.breadcrumbCurrent}>首页</span>}
      {isCases && <span className={styles.breadcrumbCurrent}>我的案件</span>}
      {isSessionList && (
        <>
          <Link to="/cases" className={styles.breadcrumbLink}>我的案件</Link>
          <span className={styles.breadcrumbSep}>/</span>
          <span className={styles.breadcrumbCurrent}>{caseDisplayName ?? '会话列表'}</span>
        </>
      )}
      {isSessionDetail && (
        <>
          <Link to="/cases" className={styles.breadcrumbLink}>我的案件</Link>
          <span className={styles.breadcrumbSep}>/</span>
          <Link to={`/cases/${caseId}/sessions`} className={styles.breadcrumbLink}>{caseDisplayName ?? caseId}</Link>
          <span className={styles.breadcrumbSep}>/</span>
          <span className={styles.breadcrumbCurrent}>会话详情</span>
        </>
      )}
      {(isReportsList || isReportPreview) && caseId && sessionId && (
        <>
          <Link to="/cases" className={styles.breadcrumbLink}>我的案件</Link>
          <span className={styles.breadcrumbSep}>/</span>
          <Link to={`/cases/${caseId}/sessions`} className={styles.breadcrumbLink}>{caseDisplayName ?? caseId}</Link>
          <span className={styles.breadcrumbSep}>/</span>
          <Link to={`/cases/${caseId}/sessions/${sessionId}`} className={styles.breadcrumbLink}>会话详情</Link>
          <span className={styles.breadcrumbSep}>/</span>
          <span className={styles.breadcrumbCurrent}>{isReportPreview ? '报告预览' : '报告列表'}</span>
        </>
      )}
      {isMyReports && (
        <>
          <span className={styles.breadcrumbCurrent}>我的报告</span>
        </>
      )}
      {pathname.startsWith('/admin/') && <span className={styles.breadcrumbCurrent}>管理员案件视图</span>}
      {!isHome && !isCases && !isSessionList && !isSessionDetail && !isReportsList && !isReportPreview && !isMyReports && !pathname.startsWith('/admin/') && (
        <span className={styles.breadcrumbCurrent}>Neo</span>
      )}
    </nav>
  )

  return (
    <div className={styles.layout}>
      <aside className={styles.sidebar}>
        <div className={styles.brand}>
          <Link to="/" className={styles.brandLogoLink} title="返回首页">
            <img
              src={theme === 'dark' ? '/logo_white.svg' : '/logo_black.svg'}
              alt="DFIR智能体平台"
              className={styles.brandLogo}
            />
          </Link>
        </div>
        <nav className={styles.nav}>
          <NavLink to="/" end className={({ isActive }) => (isActive ? `${styles.navLink} ${styles.active}` : styles.navLink)}>
            首页
          </NavLink>
          <NavLink to="/cases" className={({ isActive }) => (isActive ? `${styles.navLink} ${styles.active}` : styles.navLink)}>
            我的案件
          </NavLink>
          <NavLink to="/reports" className={({ isActive }) => (isActive ? `${styles.navLink} ${styles.active}` : styles.navLink)}>
            我的报告
          </NavLink>
        </nav>
      </aside>
      <main className={styles.main}>
        <header className={styles.topbar}>
          <div className={styles.topbarLeft}>{breadcrumb}</div>
          <div className={styles.topbarRight}>
            <button
              type="button"
              className={styles.themeToggle}
              onClick={toggleTheme}
              title={theme === 'dark' ? '切换到亮色风格' : '切换到暗色风格'}
              aria-label={theme === 'dark' ? '切换到亮色风格' : '切换到暗色风格'}
            >
              {theme === 'dark' ? '🌙' : '☀️'}
            </button>
            <div className={styles.dropdown} ref={menuRef}>
              <button type="button" className={styles.userTrigger} onClick={() => setMenuOpen((o) => !o)} aria-expanded={menuOpen}>
                <span className={styles.avatar}>{initial}</span>
                <span>{user?.username ?? '—'}</span>
                <span aria-hidden>▼</span>
              </button>
              {menuOpen && (
                <div className={styles.dropdownPanel}>
                  <div className={styles.dropdownHeader}>
                    <div className={styles.dropdownHeaderName}>{user?.username ?? '—'}</div>
                    <div className={styles.dropdownHeaderRole}>{user?.role ?? '—'}</div>
                  </div>
                  <hr className={styles.divider} />
                  {user?.role === 'admin' && (
                    <button
                      type="button"
                      className={styles.dropdownItem}
                      onClick={() => { setMenuOpen(false); setShowUserManagement(true); }}
                    >
                      用户管理
                    </button>
                  )}
                  <button type="button" className={`${styles.dropdownItem} ${styles.dropdownItemDanger}`} onClick={handleLogout}>
                    退出登录
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>
        <div className={styles.content}>
          <div className={styles.contentBody}>
            <Outlet />
          </div>
        </div>
      </main>
      {showUserManagement && <UserManagement onClose={() => setShowUserManagement(false)} />}
    </div>
  )
}
