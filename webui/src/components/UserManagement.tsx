/**
 * 用户管理模态框（仅管理员）：列表、启用/禁用、编辑角色、查看案件。
 */
import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { listUsers, updateUser } from '../api/client'
import type { UserListItem } from '../api/types'
import styles from './UserManagement.module.css'

interface UserManagementProps {
  onClose: () => void
}

export function UserManagement({ onClose }: UserManagementProps) {
  const navigate = useNavigate()
  const [users, setUsers] = useState<UserListItem[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [editEnabled, setEditEnabled] = useState(true)
  const [editRole, setEditRole] = useState('member')
  const [editPassword, setEditPassword] = useState('')

  useEffect(() => {
    loadUsers()
  }, [])

  async function loadUsers() {
    setLoading(true)
    setError(null)
    try {
      const list = await listUsers()
      setUsers(list)
    } catch (err) {
      setError(err instanceof Error ? err.message : '加载失败')
    } finally {
      setLoading(false)
    }
  }

  async function handleUpdate(userId: string) {
    setError(null)
    try {
      await updateUser(userId, {
        enabled: editEnabled,
        role: editRole,
        ...(editPassword ? { password: editPassword } : {}),
      })
      setEditingId(null)
      setEditPassword('')
      await loadUsers()
    } catch (err) {
      setError(err instanceof Error ? err.message : '保存失败')
    }
  }

  function handleViewCases(userId: string) {
    onClose()
    navigate(`/admin/users/${userId}/cases`)
  }

  return (
    <div className={styles.overlay} onClick={onClose}>
      <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
        <div className={styles.header}>
          <h2 className={styles.headerTitle}>用户管理</h2>
          <button type="button" className={styles.closeBtn} onClick={onClose} aria-label="关闭">
            ×
          </button>
        </div>
        {error && <div className={styles.errorBanner}>{error}</div>}
        <div className={styles.body}>
          {loading && !users.length ? (
            <div className={styles.loading}>加载中…</div>
          ) : (
            <table className={styles.table}>
              <thead>
                <tr>
                  <th>用户名</th>
                  <th>角色</th>
                  <th>状态</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id}>
                    <td>{u.username}</td>
                    <td>
                      {editingId === u.id ? (
                        <select
                          className={styles.roleSelect}
                          value={editRole}
                          onChange={(e) => setEditRole(e.target.value)}
                        >
                          <option value="member">普通用户</option>
                          <option value="admin">管理员</option>
                        </select>
                      ) : (
                        <span className={u.role === 'admin' ? styles.roleAdmin : styles.roleMember}>
                          {u.role === 'admin' ? '管理员' : '普通用户'}
                        </span>
                      )}
                    </td>
                    <td>
                      {editingId === u.id ? (
                        <label className={styles.checkboxLabel}>
                          <input
                            type="checkbox"
                            checked={editEnabled}
                            onChange={(e) => setEditEnabled(e.target.checked)}
                          />
                          启用
                        </label>
                      ) : (
                        <span className={u.enabled ? styles.statusOn : styles.statusOff}>
                          {u.enabled ? '启用' : '禁用'}
                        </span>
                      )}
                    </td>
                    <td>
                      {editingId === u.id ? (
                        <div className={styles.actions}>
                          <button
                            type="button"
                            className={styles.btnPrimary}
                            onClick={() => handleUpdate(u.id)}
                          >
                            保存
                          </button>
                          <button
                            type="button"
                            className={styles.btnSecondary}
                            onClick={() => { setEditingId(null); setEditPassword(''); }}
                          >
                            取消
                          </button>
                        </div>
                      ) : (
                        <div className={styles.actions}>
                          <button
                            type="button"
                            className={styles.btnSecondary}
                            onClick={() => {
                              setEditingId(u.id)
                              setEditEnabled(u.enabled)
                              setEditRole(u.role)
                              setEditPassword('')
                            }}
                          >
                            编辑
                          </button>
                          <button
                            type="button"
                            className={styles.btnLink}
                            onClick={() => handleViewCases(u.id)}
                          >
                            查看案件
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
                {editingId && (
                  <tr className={styles.passwordRow}>
                    <td colSpan={4}>
                      <div className={styles.passwordSection}>
                        <label>
                          修改密码（留空则不修改）：
                          <input
                            type="password"
                            className={styles.passwordInput}
                            value={editPassword}
                            onChange={(e) => setEditPassword(e.target.value)}
                            placeholder="至少 8 个字符"
                          />
                        </label>
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  )
}
