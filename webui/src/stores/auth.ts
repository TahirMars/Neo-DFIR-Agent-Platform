/**
 * 鉴权状态：token 存储与当前用户（与 getMe 同步）。
 */
import { getMe } from '../api/client'
import type { MeResponse } from '../api/types'

const TOKEN_KEY = 'neo_token'

export function getStoredToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setStoredToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token)
}

export function clearStoredToken(): void {
  localStorage.removeItem(TOKEN_KEY)
}

export function isAuthenticated(): boolean {
  return !!getStoredToken()
}

/** 当前用户信息（由 getMe 填充，未登录为 null） */
export type AuthUser = MeResponse | null

export { getMe }
