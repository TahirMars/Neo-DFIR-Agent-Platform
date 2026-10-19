---
id: hunting-for-living-off-the-cloud-techniques
name: hunting-for-living-off-the-cloud-techniques
name_zh: 威胁狩猎·离地·离地·云·技术
description: 猎杀滥用合法云服务进行 C2、数据暂存与外泄的行为，包括对 Azure、AWS、GCP 及 SaaS 平台的滥用（Living off the
  Cloud）。
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- mitre-attack
- cloud-abuse
- c2
- lotc
- saas
- proactive-detection
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 威胁狩猎·离地·离地·云·技术

## 使用时机

- 在环境中主动猎杀云上离地技术相关指标
- 威胁情报表明活跃攻击活动使用此类技术之后
- 事件响应中界定与这些技术相关的沦陷范围
- EDR 或 SIEM 告警触发相关指标时
- 定期安全评估与紫队演练期间

## 前置条件

- 具备进程与网络遥测的 EDR（CrowdStrike、MDE、SentinelOne）
- 已接入相关日志的 SIEM（Splunk、Elastic、Sentinel）
- 全面配置的 Sysmon 部署
- Windows 安全事件日志转发已启用
- 用于 IOC 关联的威胁情报源

## 工作流程

1. **形成假设**：基于威胁情报或 ATT&CK 缺口分析提出可检验假设。
2. **识别数据源**：确定验证或否定假设所需的日志与遥测。
3. **执行查询**：在 SIEM 与 EDR 上运行检测查询收集相关事件。
4. **分析结果**：审视查询结果中的异常，跨数据源关联。
5. **验证发现**：结合上下文区分真阳性与误报。
6. **关联活动**：将发现与更广攻击链及威胁体 TTP 关联。
7. **记录与报告**：记录发现、更新检测规则并建议响应动作。

## 关键概念

| 概念 | 说明 |
|---------|-------------|
| T1102 | Web 服务 |
| T1567 | 经 Web 服务外泄 |
| T1537 | 转移至云账户 |

## 工具与系统

| 工具 | 用途 |
|------|---------|
| CrowdStrike Falcon | EDR 遥测与威胁检测 |
| Microsoft Defender for Endpoint | 高级搜寻（KQL） |
| Splunk Enterprise | SPL 日志分析 SIEM |
| Elastic Security | 检测规则与调查时间线 |
| Sysmon | 详细 Windows 事件监控 |
| Velociraptor | 端点工件采集与猎杀 |
| Sigma 规则 | 跨平台检测规则格式 |

## 常见场景

1. **场景 1**：经 Discord Webhook 投递 C2 指令
2. **场景 2**：数据外泄至 Telegram Bot API
3. **场景 3**：恶意软件使用 Azure Functions 作动态 C2
4. **场景 4**：在 Google Docs 或 Notion 页面暂存窃取数据

## 输出格式

```
猎杀 ID: TH-HUNTIN-[DATE]-[SEQ]
技术: T1102
主机: [主机名]
用户: [账户上下文]
证据: [日志项、进程树、网络数据]
风险级别: [严重/高/中/低]
置信度: [高/中/低]
建议动作: [遏制、调查、持续监控]
```