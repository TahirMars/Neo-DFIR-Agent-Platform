/**
 * 路由守卫：未登录时重定向到登录页。
 */
import { Navigate, useLocation } from 'react-router-dom'
import { getStoredToken } from '../stores/auth'

export function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const location = useLocation()
  const token = getStoredToken()
  if (!token) {
    return <Navigate to="/login" state={{ from: location.pathname + location.search }} replace />
  }
  return <>{children}</>
}
