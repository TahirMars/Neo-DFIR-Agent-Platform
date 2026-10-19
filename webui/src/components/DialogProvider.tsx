/**
 * 全局弹窗 Provider：提供 useDialog() hook，替代原生 window.confirm / window.prompt。
 * 支持暗色/亮色主题，风格与平台统一。
 */
import { createContext, useContext, useState, useCallback, useRef, useEffect } from 'react'
import type { ReactNode } from 'react'
import styles from './Dialog.module.css'

interface DialogOptions {
  title?: string
  confirmText?: string
  cancelText?: string
  danger?: boolean
}

interface ConfirmFn {
  (message: string, options?: DialogOptions): Promise<boolean>
}

interface PromptFn {
  (message: string, defaultValue?: string, options?: DialogOptions): Promise<string | null>
}

interface DialogContextValue {
  confirm: ConfirmFn
  prompt: PromptFn
}

const DialogContext = createContext<DialogContextValue | null>(null)

export function useDialog(): DialogContextValue {
  const ctx = useContext(DialogContext)
  if (!ctx) throw new Error('useDialog 必须在 <DialogProvider> 内使用')
  return ctx
}

type DialogState =
  | null
  | { mode: 'confirm'; message: string; options: DialogOptions; resolve: (v: boolean) => void }
  | { mode: 'prompt'; message: string; defaultValue: string; options: DialogOptions; resolve: (v: string | null) => void }

export function DialogProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<DialogState>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (state?.mode === 'prompt' && inputRef.current) {
      inputRef.current.focus()
      inputRef.current.select()
    }
  }, [state])

  useEffect(() => {
    if (!state) return
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') handleCancel()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  })

  const confirm = useCallback<ConfirmFn>((message, options = {}) => {
    return new Promise<boolean>((resolve) => {
      setState({ mode: 'confirm', message, options, resolve })
    })
  }, [])

  const prompt = useCallback<PromptFn>((message, defaultValue = '', options = {}) => {
    return new Promise<string | null>((resolve) => {
      setState({ mode: 'prompt', message, defaultValue, options, resolve })
    })
  }, [])

  function handleConfirm() {
    if (!state) return
    if (state.mode === 'confirm') {
      state.resolve(true)
    } else {
      state.resolve(inputRef.current?.value ?? state.defaultValue)
    }
    setState(null)
  }

  function handleCancel() {
    if (!state) return
    if (state.mode === 'confirm') {
      state.resolve(false)
    } else {
      state.resolve(null)
    }
    setState(null)
  }

  const isDanger = state?.options.danger ?? false
  const title = state?.options.title ?? (state?.mode === 'confirm' ? (isDanger ? '确认操作' : '提示') : '请输入')
  const confirmText = state?.options.confirmText ?? (isDanger ? '删除' : '确认')
  const cancelText = state?.options.cancelText ?? '取消'
  const icon = isDanger ? '⚠️' : state?.mode === 'prompt' ? '✏️' : 'ℹ️'

  return (
    <DialogContext.Provider value={{ confirm, prompt }}>
      {children}
      {state && (
        <div className={styles.overlay} onClick={(e) => { if (e.target === e.currentTarget) handleCancel() }}>
          <div className={styles.dialog} role="dialog" aria-modal="true">
            <div className={styles.header}>
              <div className={`${styles.icon} ${isDanger ? styles.iconDanger : styles.iconPrimary}`}>
                {icon}
              </div>
              <h2 className={styles.title}>{title}</h2>
            </div>
            <div className={styles.body}>
              <p className={styles.message}>{state.message}</p>
              {state.mode === 'prompt' && (
                <div className={styles.inputWrap}>
                  <input
                    ref={inputRef}
                    type="text"
                    className={styles.input}
                    defaultValue={state.defaultValue}
                    onKeyDown={(e) => { if (e.key === 'Enter') handleConfirm() }}
                    placeholder="请输入..."
                  />
                </div>
              )}
            </div>
            <div className={styles.footer}>
              <button type="button" className={styles.btnCancel} onClick={handleCancel}>{cancelText}</button>
              <button
                type="button"
                className={`${styles.btnConfirm} ${isDanger ? styles.btnDanger : styles.btnPrimary}`}
                onClick={handleConfirm}
              >
                {confirmText}
              </button>
            </div>
          </div>
        </div>
      )}
    </DialogContext.Provider>
  )
}
