---
id: analyzing-powershell-empire-artifacts
name: analyzing-powershell-empire-artifacts
name_zh: 分析·PowerShell·Empire·取证痕迹
description: 通过识别脚本块日志记录事件中的Base64编码启动器模式、默认用户代理、暂存URL结构、暂存器IOC和已知Empire模块签名，检测Windows事件日志中的PowerShell
  Empire框架工件。
domain: cybersecurity
subdomain: threat-hunting
tags:
- PowerShell-Empire
- threat-hunting
- Script-Block-Logging
- base64
- stager
- C2
- MITRE-ATT&CK
- T1059.001
- forensics
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 分析 PowerShell Empire 取证痕迹

## 概述
PowerShell Empire 是一个后开发框架，由侦听器、暂存器和代理组成。其工件在 Windows 事件日志中留下可检测的痕迹，特别是 PowerShell 脚本块日志记录（事件 ID 4104）和模块日志记录（事件 ID 4103）。此技能分析 Empire 的默认启动器字符串（`powershell -noP -sta -w 1 -enc`）、包含`System.Net.WebClient`和`FromBase64String`的 Base64 编码有效负载、已知模块调用（Invoke-Mimikatz、Invoke-Kerberoast、Invoke-TokenManipulation）和暂存 URL 模式的事件日志。

## 使用时机
- 在调查需要分析 PowerShell Empire 工件的安全事件时
- 为该域构建检测规则或威胁搜寻查询时
- 当 SOC 分析师需要这种分析类型的结构化程序时
- 验证相关攻击技术的安全监控覆盖范围时

## 前置条件
- Python 3.9+ 可访问 Windows 事件日志或导出的 EVTX 文件
- 通过组策略启用 PowerShell 脚本块日志记录（事件 ID 4104）
- 启用模块日志记录（事件 ID 4103）以实现全面覆盖

## 关键检测模式

1. **默认启动器** — `powershell -noP -sta -w 1 -enc` 后跟 Base64 blob
2. **阶段指标** — `System.Net.WebClient`、`DownloadData`、`DownloadString`、`FromBase64String`
3. **模块签名** — Invoke-Mimikatz、Invoke-Kerberoast、Invoke-TokenManipulation、Invoke-PSInject、Invoke-DCOM
4. **用户代理字符串** — HTTP 侦听器配置中的默认 Empire 用户代理
5. **暂存 URL** — `/login/process.php`、`/admin/get.php` 和类似的默认 URI 模式

## 输出

JSON 报告，其中包含匹配的 IOC、解码的 Base64 有效负载、可疑事件的时间线、MITRE ATT&CK 技术映射和严重性评分。