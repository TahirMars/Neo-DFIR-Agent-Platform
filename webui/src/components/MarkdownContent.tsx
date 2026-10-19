/**
 * 通用 Markdown 渲染组件：支持 GFM 表格、Mermaid 图、代码块复制。
 * 在对话聊天框和报告预览中统一使用。
 */
import { useCallback } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { MermaidDiagram } from './MermaidDiagram'
import styles from './MarkdownContent.module.css'

interface MarkdownContentProps {
  content: string
  className?: string
}

export function MarkdownContent({ content, className }: MarkdownContentProps) {
  const copyCode = useCallback((text: string) => {
    navigator.clipboard?.writeText(text)
  }, [])

  const components = {
    pre: ({ children }: { children?: React.ReactNode }) => {
      const child = Array.isArray(children) ? children[0] : children
      const codeProps =
        child && typeof child === 'object' && 'props' in child
          ? (child as React.ReactElement<{ className?: string; children?: React.ReactNode }>).props
          : undefined
      const lang = /language-(\w+)/.exec(codeProps?.className ?? '')?.[1]
      const code = String(codeProps?.children ?? '').replace(/\n$/, '')

      if (lang === 'mermaid') {
        return <MermaidDiagram chart={code} />
      }

      return (
        <div className={styles.codeBlock} data-code-block>
          <div className={styles.codeBlockBar}>
            {lang && <span className={styles.codeLang}>{lang}</span>}
            <button
              type="button"
              className={styles.copyBtn}
              onClick={() => copyCode(code)}
            >
              复制
            </button>
          </div>
          <pre><code>{code}</code></pre>
        </div>
      )
    },
    table: ({ children, ...props }: React.HTMLAttributes<HTMLTableElement>) => (
      <div className={styles.tableWrap}>
        <table {...props}>{children}</table>
      </div>
    ),
  }

  return (
    <div className={`${styles.markdown} ${className ?? ''}`}>
      <ReactMarkdown remarkPlugins={[remarkGfm]} components={components}>
        {content}
      </ReactMarkdown>
    </div>
  )
}
