---
id: hunting-for-startup-folder-persistence
name: hunting-for-startup-folder-persistence
name_zh: 猎杀·启动文件夹·持久化
description: 通过监控 Windows 启动目录中的可疑文件创建、分析 autoruns 项及使用 Python watchdog 实时监控文件系统，检测
  T1547.001 启动文件夹持久化。
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- T1547.001
- startup-folder
- persistence
- autoruns
- watchdog
- filesystem-monitoring
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 猎杀启动文件夹持久化

## 概述

攻击者使用 Windows 启动文件夹实现持久化（MITRE ATT&CK T1547.001——启动或登录自动启动执行：注册表 Run 键/启动文件夹）。置于 `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` 或 `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup` 的文件会在用户登录时自动执行。本技能扫描启动目录中的可疑文件，使用 Python watchdog 实时监控变更，并分析文件元数据以检测持久化植入。


## 使用时机

- 调查需要猎杀启动文件夹持久化的安全事件
- 为该领域构建检测规则或威胁猎杀查询
- SOC 分析师需要该分析类型的结构化流程
- 验证与相关攻击技术相关的安全监控覆盖

## 前置条件

- Python 3.9+，含 `watchdog`、`pefile`（可选，用于 PE 分析）
- 可访问 Windows 启动文件夹（用户与所有用户）
- 用于与事件 ID 4663 关联的 Windows 事件日志（可选）

## 步骤

1. 枚举用户与系统启动目录中的所有文件
2. 分析文件类型、创建时间戳与数字签名
3. 标记可疑扩展名（.bat、.vbs、.ps1、.lnk、.exe）
4. 检查 7 天内新建文件作为潜在植入
5. 使用 watchdog FileSystemEventHandler 实时监控启动文件夹
6. 与已知合法启动项关联
7. 生成含 T1547.001 MITRE 映射的威胁猎杀报告

## 预期输出

- JSON 报告：列出启动文件夹内容、风险分、文件元数据与可疑指标
- 启动目录新建文件的实时监控告警