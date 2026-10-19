---
id: hunting-for-process-injection-techniques
name: hunting-for-process-injection-techniques
name_zh: 猎杀·进程注入·技术
description: 通过 Sysmon 事件 ID 8、10 与 EDR 进程遥测，检测 CreateRemoteThread、进程镂空、DLL 注入等进程注入技术（MITRE
  T1055）。
domain: cybersecurity
subdomain: threat-hunting
tags:
- process-injection
- t1055
- sysmon
- createremotethread
- dll-injection
- edr
- threat-hunting
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 猎杀进程注入技术

## 概述

进程注入（MITRE ATT&CK T1055）使对手能在另一进程地址空间中执行代码，用于规避检测与提权。本技能通过 Sysmon 事件 ID 8（CreateRemoteThread）、事件 ID 10（含可疑访问权限的 ProcessAccess）及源-目标进程关系分析，区分合法与恶意注入。


## 使用时机

- 调查需要猎杀进程注入技术的安全事件
- 为该领域构建检测规则或威胁猎杀查询
- SOC 分析师需要该分析类型的结构化流程
- 验证与相关攻击技术相关的安全监控覆盖

## 前置条件

- 已安装 Sysmon 并启用事件 ID 8 与 10
- 进程创建日志（Sysmon 事件 ID 1 或 Windows 4688）
- Python 3.8+ 标准库
- JSON 格式的 Sysmon 事件日志

## 步骤

1. **解析 Sysmon 事件** — 从 JSON 日志摄取事件 ID 1、8、10
2. **检测 CreateRemoteThread** — 标记事件 ID 8 中可疑的源-目标进程对
3. **分析 ProcessAccess 权限** — 识别含危险访问掩码的事件 ID 10（PROCESS_VM_WRITE、PROCESS_CREATE_THREAD）
4. **构建进程关系图** — 映射源到目标的注入关系
5. **过滤已知合法对** — 排除已知良性注入模式（杀软、调试器、系统进程）
6. **注入严重度评分** — 根据源进程、目标进程与访问权限风险评分
7. **生成猎杀报告** — 产出结构化报告及 MITRE 子技术映射

## 预期输出

- 含严重度评分的检出注入事件 JSON 报告
- 进程注入关系图
- MITRE ATT&CK 子技术映射（T1055.001–T1055.012）
- 误报排除建议