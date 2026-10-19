/**
 * Mermaid 图表渲染组件。
 * 语法错误时 mermaid.render 仍会 resolve，但返回内含巨型错误提示的 SVG；
 * 因此先 parse 校验，并对返回 SVG 做错误图检测，避免把错误图塞进正文造成版面混乱。
 *
 * 必须向 mermaid.render 传入第三参数（挂载容器）：否则 Mermaid 会向 document.body 注入临时节点，
 * 在抛错或 StrictMode 双调用时易残留，表现为整页底部出现黑色长条。
 */
import { useEffect, useRef, useState } from 'react'
import mermaid from 'mermaid'
import styles from './MermaidDiagram.module.css'

mermaid.initialize({
  startOnLoad: false,
  theme: 'dark',
  securityLevel: 'loose',
})

interface MermaidDiagramProps {
  chart: string
  id?: string
}

let counter = 0

/** 清除可能泄漏到 document 的临时节点（id / d{id} / i{id}） */
function removeMermaidDomArtifacts(renderId: string) {
  document.getElementById(`d${renderId}`)?.remove()
  document.getElementById(`i${renderId}`)?.remove()
  document.getElementById(renderId)?.remove()
}

/** Mermaid 在解析失败时生成的占位 SVG 特征（见 mermaid.core.mjs 中 error-text / error-icon） */
function isMermaidErrorSvg(svg: string): boolean {
  return svg.includes('class="error-text"') || svg.includes('class="error-icon"')
}

type RenderState =
  | { kind: 'loading' }
  | { kind: 'ok'; svg: string }
  /** detail 为 null 表示已拦截内置错误图，仅展示简短说明 */
  | { kind: 'fail'; detail: string | null }

export function MermaidDiagram({ chart, id }: MermaidDiagramProps) {
  const hostRef = useRef<HTMLDivElement>(null)
  const [renderState, setRenderState] = useState<RenderState>({ kind: 'loading' })
  const stableId = useRef(id || `mermaid-${++counter}`)

  useEffect(() => {
    if (!chart.trim()) return
    let cancelled = false
    setRenderState({ kind: 'loading' })
    ;(async () => {
      const host = hostRef.current
      if (!host) {
        setRenderState({ kind: 'fail', detail: '内部容器未就绪' })
        return
      }
      try {
        await mermaid.parse(chart)
        const { svg: s } = await mermaid.render(stableId.current, chart, host)
        if (cancelled) return
        if (isMermaidErrorSvg(s)) {
          setRenderState({ kind: 'fail', detail: null })
          return
        }
        setRenderState({ kind: 'ok', svg: s })
      } catch (e) {
        if (!cancelled) {
          const msg = e instanceof Error ? e.message : String(e)
          setRenderState({ kind: 'fail', detail: msg || null })
        }
      } finally {
        host.innerHTML = ''
        removeMermaidDomArtifacts(stableId.current)
      }
    })()
    return () => {
      cancelled = true
      const host = hostRef.current
      if (host) host.innerHTML = ''
      removeMermaidDomArtifacts(stableId.current)
    }
  }, [chart])

  if (!chart.trim()) {
    return null
  }

  const shell = (
    <>
      <div ref={hostRef} className={styles.renderHost} aria-hidden />
      {renderState.kind === 'loading' && (
        <div className="mermaid-loading" style={{ padding: 12, color: 'rgba(255,255,255,0.5)' }}>
          渲染中…
        </div>
      )}
      {renderState.kind === 'fail' && (
        <div className="mermaid-error">
          <div className="mermaid-error-title">无法渲染图表（语法无效或当前版本不支持）</div>
          {renderState.detail && (
            <details className="mermaid-error-details">
              <summary>技术详情</summary>
              <pre>{renderState.detail}</pre>
            </details>
          )}
          <details className="mermaid-error-details">
            <summary>查看源码</summary>
            <pre>{chart}</pre>
          </details>
        </div>
      )}
      {renderState.kind === 'ok' && (
        <div className="mermaid-container" dangerouslySetInnerHTML={{ __html: renderState.svg }} />
      )}
    </>
  )

  return <>{shell}</>
}
