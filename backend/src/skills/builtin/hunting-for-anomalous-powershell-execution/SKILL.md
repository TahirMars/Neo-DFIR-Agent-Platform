---
name: hunting-for-anomalous-powershell-execution
id: hunting-for-anomalous-powershell-execution
description: '通过分析脚本块日志（事件 4104）、模块日志（事件 4103）与进程创建事件狩猎恶意 PowerShell 活动。 解析 Windows
  事件日志 EVTX，检测混淆命令、AMSI 绕过尝试、编码载荷、凭据转储关键词与可疑下载 cradle。 在涉及 PowerShell 威胁狩猎、脚本块分析、编码命令检测或
  AMSI 绕过识别的请求时启用。

  '
domain: cybersecurity
subdomain: threat-hunting
tags:
- powershell
- script-block-logging
- event-4104
- amsi
- threat-hunting
- evtx
- obfuscation
version: '1.0'
author: mahipal
license: Apache-2.0
neo_agents:
- forensic
- general_chat
---

# 狩猎异常 PowerShell 执行

## 概述

PowerShell 脚本块日志（事件 ID 4104）记录 Windows 终端上执行的完整去混淆脚本文本，是狩猎恶意 PowerShell 的主要数据源。结合模块日志（4103）与进程创建事件，分析人员可检测编码命令、AMSI 绕过模式、下载 cradle、凭据窃取工具与无文件技术，即便攻击者使用多层混淆。

## 何时使用

- 需要狩猎异常 PowerShell 执行的安全事件时
- 为该领域构建检测规则或威胁狩猎查询时
- SOC 分析师需要该分析类型的结构化流程时
- 验证与相关攻击技术的安全监控覆盖时

## 先决条件

- 来自 Microsoft-Windows-PowerShell/Operational 的 Windows 事件日志导出（.evtx）
- Python 3.8+，安装 python-evtx 与 lxml
- 已通过组策略启用脚本块日志
- 了解常见 PowerShell 攻击技术

## 步骤

1. 解析 EVTX，提取事件 4104 的脚本块文本与元数据
2. 使用 ScriptBlock ID 关联重组多段脚本块
3. 扫描脚本文本中的 AMSI 绕过指标与混淆模式
4. 检测编码命令执行与 base64 载荷
5. 识别下载 cradle、凭据转储与横向移动命令
6. 按威胁严重程度评分并排序发现

## 预期输出

```json
{
  "total_events": 1247,
  "suspicious_events": 23,
  "amsi_bypass_attempts": 2,
  "encoded_commands": 8,
  "download_cradles": 5,
  "credential_access": 3
}
```