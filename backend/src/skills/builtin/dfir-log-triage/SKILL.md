---
id: dfir-log-triage
name: 日志初筛与优先级
description: 取证分析前对日志文件做优先级排序：大文件先结构化摘要、再精读高价值片段，并提醒常见 DFIR 误报（如内网扫描误当 C2）。
neo_agents:
  - forensic
  - general_chat
---

## 工作流建议

1. 使用 `evidence_ls_tool(only_classified_logs=True)` 获取清单，按扩展名与大小分类（取证解析与过滤/时间线实现位于 `src.tools.evidence_analysis`）。
2. 大于约 30KB 的文本/表格类日志优先 `evidence_read_tool(..., structured=True)`（底层 `parse_evidence_structured`）；避免单次 `evidence_read_tool` 行数过大撑满上下文。
3. 对 Web/代理/防火墙日志，先找异常状态码、罕见 User-Agent、非常规路径。
4. 对 Windows 事件类，关注登录失败突增、新服务/计划任务、PowerShell 编码执行。

## 注意

- 不要把 RFC1918 内网 IP 默认标为恶意，除非日志上下文表明异常横向或 C2。
- 时间戳缺失时标注「时间未知」，勿编造。

## 工具引用

- 列目录：`evidence_ls_tool`（`only_classified_logs=True` 仅看分类为日志/文本的路径）
- 结构化解析：`evidence_read_tool(..., structured=True)`（与 Python `parse_evidence_structured` 对应）
- 按行分页 / 检索：`evidence_read_tool`、`evidence_grep_tool`
- 情报：`query_threat_intel`（在确认高可疑 IOC 后使用）
