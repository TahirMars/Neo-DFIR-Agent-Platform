---
name: hunting-for-data-staging-before-exfiltration
id: hunting-for-data-staging-before-exfiltration
description: 通过 EDR 与进程遥测监控 7-Zip/RAR 等归档创建、异常临时目录访问、大文件合并与暂存目录模式，检测外泄前的数据暂存活动。
domain: cybersecurity
subdomain: threat-hunting
tags:
- data-staging
- exfiltration
- t1074
- archive-detection
- edr
- threat-hunting
- dlp
version: '1.0'
author: mahipal
license: Apache-2.0
neo_agents:
- forensic
- general_chat
---

# 狩猎外泄前的数据暂存

## 概述

在外泄数据前，对手通常将收集的文件集中到一处（MITRE ATT&CK T1074），包括使用 7-Zip、RAR 或 tar 创建归档、从多目录合并文件，以及使用临时或隐藏暂存目录。本技能通过分析进程创建日志中的压缩工具活动、监控常见暂存路径上的文件系统事件，以及识别异常文件合并模式来检测暂存行为。

## 何时使用

- 需要狩猎外泄前数据暂存相关安全事件时
- 为该领域构建检测规则或威胁狩猎查询时
- SOC 分析师需要该分析类型的结构化流程时
- 验证与相关攻击技术的安全监控覆盖时

## 先决条件

- 具备进程创建与文件系统事件的 EDR 或 Sysmon 遥测
- Windows 事件日志（事件 ID 4688）或 Sysmon 事件 ID 1、11
- Python 3.8+ 标准库
- JSON/CSV 格式的进程创建日志访问权限

## 步骤

1. **检测压缩工具执行** — 监控带压缩参数的 7z.exe、rar.exe、tar、zip、WinRAR 进程创建
2. **识别暂存目录** — 标记写入常见暂存位置（回收站、%TEMP%、ProgramData、隐藏目录）的文件
3. **检测大文件合并** — 识别多次文件读取后写入单一目录的模式
4. **监控敏感路径访问** — 跟踪从文档目录、数据库路径与网络共享的大量读取
5. **分析归档元数据** — 提取并分析归档大小、创建时间与源路径
6. **暂存风险评分** — 根据归档大小、源多样性、暂存路径可疑性与时间应用启发式评分
7. **生成狩猎报告** — 产出含暂存事件时间线与 MITRE ATT&CK 映射的结构化报告

## 预期输出

- 含风险分的已检测暂存事件 JSON 报告
- 含源文件分析的归档创建时间线
- MITRE ATT&CK 映射（T1074.001、T1074.002、T1560）
- 显示可疑写入活动的暂存目录热力图