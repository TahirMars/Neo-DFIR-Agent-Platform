/**
 * 统一 ID 格式常量与校验。
 * 所有实体 ID 格式: {prefix}-{12位十六进制}
 *   案件   case-93d4e4c82dec
 *   会话   session-453e082cff8a
 *   证据   ev-52598b8403a8
 *   报告   report-7f3a1b2c4d5e
 *   消息   msg-a1b2c3d4e5f6
 */

export const ID_PREFIX = {
  CASE: 'case',
  SESSION: 'session',
  EVIDENCE: 'ev',
  REPORT: 'report',
  MESSAGE: 'msg',
} as const

const ID_PATTERNS: Record<string, RegExp> = {
  [ID_PREFIX.CASE]: /^case-[0-9a-f]{12}$/,
  [ID_PREFIX.SESSION]: /^session-[0-9a-f]{12}$/,
  [ID_PREFIX.EVIDENCE]: /^ev-[0-9a-f]{12}$/,
  [ID_PREFIX.REPORT]: /^report-[0-9a-f]{12}$/,
  [ID_PREFIX.MESSAGE]: /^msg-[0-9a-f]{12}$/,
}

const GENERIC_PATTERN = /^[a-z]+-[0-9a-f]{12}$/

export function isValidId(value: string, prefix?: string): boolean {
  if (!value) return false
  if (prefix && ID_PATTERNS[prefix]) {
    return ID_PATTERNS[prefix].test(value)
  }
  return GENERIC_PATTERN.test(value)
}

export function formatIdShort(id: string): string {
  const dash = id.indexOf('-')
  if (dash === -1) return id
  return `${id.slice(0, dash)}-${id.slice(dash + 1, dash + 5)}…`
}
