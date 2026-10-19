---
id: hunting-for-spearphishing-indicators
name: hunting-for-spearphishing-indicators
name_zh: 猎杀·鱼叉式钓鱼·指标
description: 跨邮件日志、端点遥测与网络数据猎杀鱼叉式钓鱼活动指标，检测针对性邮件攻击（MITRE T1566）。
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- mitre-attack
- spearphishing
- initial-access
- email-security
- t1566
- proactive-detection
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 猎杀鱼叉式钓鱼指标

## 使用时机

- 在环境中主动猎杀鱼叉式钓鱼相关指标
- 威胁情报表明活跃活动使用这些技术
- 事件响应中界定相关沦陷范围
- EDR 或 SIEM 触发相关指标时
- 定期安全评估与紫队演练

## 前置条件

- 具备进程与网络遥测的 EDR（CrowdStrike、MDE、SentinelOne）
- 已接入相关日志的 SIEM（Splunk、Elastic、Sentinel）
- 全面配置的 Sysmon
- Windows 安全事件日志转发已启用
- 用于 IOC 关联的威胁情报源

## 工作流程

1. **形成假设**：基于威胁情报或 ATT&CK 缺口提出可检验假设。
2. **识别数据源**：确定验证假设所需的日志与遥测。
3. **执行查询**：在 SIEM 与 EDR 上运行检测查询。
4. **分析结果**：审视异常并跨源关联。
5. **验证发现**：区分真阳性与误报。
6. **关联活动**：与更广攻击链及威胁体 TTP 关联。
7. **记录与报告**：记录发现、更新规则并建议响应。

## 关键概念

| 概念 | 说明 |
|---------|-------------|
| T1566.001 | 鱼叉式钓鱼附件 |
| T1566.002 | 鱼叉式钓鱼链接 |
| T1566.003 | 经服务的鱼叉式钓鱼 |

## 工具与系统

| 工具 | 用途 |
|------|---------|
| CrowdStrike Falcon | EDR 遥测与检测 |
| Microsoft Defender for Endpoint | KQL 高级搜寻 |
| Splunk Enterprise | SPL SIEM 分析 |
| Elastic Security | 检测规则与时间线 |
| Sysmon | 详细 Windows 监控 |
| Velociraptor | 端点采集与猎杀 |
| Sigma 规则 | 跨平台检测格式 |

## 常见场景

1. **场景 1**：含宏 Excel 执行 PowerShell 下载器
2. **场景 2**：HTML 走私投递带 LNK 的 ISO
3. **场景 3**：伪装 SharePoint 通知的凭据钓鱼链接
4. **场景 4**：PDF 附件中的二维码钓鱼

## 输出格式

```
猎杀 ID: TH-HUNTIN-[DATE]-[SEQ]
技术: T1566.001
主机: [主机名]
用户: [账户上下文]
证据: [日志、进程树、网络数据]
风险级别: [严重/高/中/低]
置信度: [高/中/低]
建议动作: [遏制、调查、监控]
```