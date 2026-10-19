/** 与后端 sessions SSE agent_meta_map 一致 */
export const STREAM_AGENT_META: Record<string, { label: string; icon: string }> = {
  supervisor: { label: 'Neo智能体', icon: '\u{1F916}' },
  forensic_agent: { label: '取证分析', icon: '\u{1F50D}' },
  sample_agent: { label: '样本分析', icon: '\u{1F9EC}' },
  report_generator: { label: '报告生成', icon: '\u{1F4CB}' },
  general_chat: { label: 'DFIR专家', icon: '\u{1F4AC}' },
  default: { label: '助手', icon: '\u{1F4AC}' },
}
