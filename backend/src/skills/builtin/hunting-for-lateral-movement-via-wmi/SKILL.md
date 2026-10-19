---
id: hunting-for-lateral-movement-via-wmi
name: hunting-for-lateral-movement-via-wmi
name_zh: 威胁狩猎·横向·移动·WMI
description: 通过分析 Windows 事件 ID 4688 进程创建与 Sysmon 事件 ID 1，检测 WmiPrvSE.exe 子进程模式、远程进程执行及
  WMI 事件订阅持久化，以发现基于 WMI 的横向移动。
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- lateral-movement
- wmi
- sysmon
- mitre-attack
- process-creation
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 威胁狩猎·横向·移动·WMI

## 概述

Windows Management Instrumentation（WMI）常被滥用进行横向移动，例如通过 `wmic process call create` 或 Win32_Process.Create() 在远程主机执行命令。检测重点为在 Windows 安全事件 ID 4688 与 Sysmon 事件 ID 1 中识别 WmiPrvSE.exe 派生子进程（cmd.exe、powershell.exe），以及 WMI-Activity/Operational 日志（5857、5860、5861）中的事件订阅持久化。


## 使用时机

- 调查需要猎杀经 WMI 横向移动的安全事件
- 为该领域构建检测规则或威胁猎杀查询
- SOC 分析师需要该分析类型的结构化流程
- 验证与相关攻击技术相关的安全监控覆盖

## 前置条件

- 已启用进程创建审核的 Windows 安全事件日志（事件 4688，含命令行）
- 已安装 Sysmon 并配置事件 ID 1（进程创建）
- Python 3.9+，含 `python-evtx`、`lxml`
- 了解 WMI 架构与 WmiPrvSE.exe 行为

## 步骤

### 第 1 步：解析进程创建事件
从 EVTX 提取事件 ID 4688 与 Sysmon 事件 1。

### 第 2 步：检测 WmiPrvSE 子进程
标记 ParentImage/ParentProcessName 为 WmiPrvSE.exe 的进程，表示远程 WMI 执行。

### 第 3 步：分析命令行模式
识别符合 WMI 横向移动模式的命令行（如 cmd.exe /q /c、重定向到 admin$ 共享）。

### 第 4 步：检查 WMI 事件订阅
解析 WMI-Activity/Operational 日志中事件消费者创建，指示持久化。

## 预期输出

JSON 报告：WMI 派生进程、可疑命令行、WMI 事件订阅告警及横向移动活动时间线。