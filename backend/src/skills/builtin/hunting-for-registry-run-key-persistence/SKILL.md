---
id: hunting-for-registry-run-key-persistence
name: hunting-for-registry-run-key-persistence
name_zh: 猎杀·注册表·Run·键·持久化
description: 通过分析 Sysmon 事件 ID 13 与注册表查询，检测 MITRE ATT&CK T1547.001 注册表 Run 键持久化及恶意自启动项。
domain: cybersecurity
subdomain: threat-hunting
tags:
- persistence
- registry-run-keys
- t1547-001
- sysmon
- threat-hunting
- windows-forensics
- mitre-attack
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 猎杀注册表 Run 键持久化

## 概述

注册表 Run 键（T1547.001）是对手最常用的持久化方式之一。程序写入 Windows 注册表 Run 键后会在用户登录时自动执行。攻击者滥用 `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`、`HKCU\Software\Microsoft\Windows\CurrentVersion\Run` 及其 RunOnce 等键维持驻留。Sysmon 事件 ID 13（RegistryEvent - Value Set）记录注册表值修改，含目标对象路径、修改进程与新值。检测需监控临时目录中的可疑可执行文件、编码 PowerShell、LOLBin 路径及通常不创建 Run 键的进程。将事件 13 与事件 1（进程创建）、11（文件创建）链式关联可强化检测。


## 使用时机

- 调查需要猎杀注册表 Run 键持久化的安全事件
- 为该领域构建检测规则或威胁猎杀查询
- SOC 分析师需要该分析类型的结构化流程
- 验证与相关攻击技术相关的安全监控覆盖

## 前置条件

- Windows 系统已安装 Sysmon 并配置记录事件 ID 13
- Sysmon 配置含 Run/RunOnce 键的 RegistryEvent 规则
- Python 3.9+，含 `json`、`xml.etree.ElementTree`、`re`
- 汇聚 Sysmon 日志的 SIEM 或日志平台（Splunk、Elastic、Sentinel）
- 用于基线对比的合法自启动程序知识

## 步骤

1. 采集过滤 Run/RunOnce 路径的 Sysmon 事件 ID 13 日志
2. 解析事件 XML/JSON，提取 TargetObject、Details（写入值）、Image（修改进程）
3. 标记指向临时目录、AppData 或 ProgramData 的值
4. 检测注册表值中的编码 PowerShell 或脚本解释器
5. 识别 LOLBin 滥用（mshta.exe、rundll32.exe、regsvr32.exe、wscript.exe）
6. 与已知良好自启动基线比对
7. 检查修改进程（Image）是否异常（cmd.exe、powershell.exe、python.exe）
8. 与事件 ID 1 链式关联，确认注册的可执行文件是否新近创建
9. 生成含 MITRE 映射与严重度评分的检测报告
10. 从发现生成 Sigma/Splunk 检测规则

## 预期输出

JSON 报告：列出可疑 Run 键项，含注册表路径、写入值、修改进程、时间戳、MITRE 技术映射、严重度评级及建议 Sigma 检测规则。