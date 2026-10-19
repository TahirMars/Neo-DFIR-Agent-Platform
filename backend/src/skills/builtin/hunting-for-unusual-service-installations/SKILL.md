---
id: hunting-for-unusual-service-installations
name: hunting-for-unusual-service-installations
name_zh: 猎杀·异常·服务·安装
description: 通过解析系统事件日志中的事件 ID 7045、分析服务二进制路径与持久化指标，检测可疑 Windows 服务安装（MITRE T1543.003）。
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- T1543.003
- service-installation
- persistence
- Event-7045
- Sysmon
- Windows-services
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 猎杀异常服务安装

## 概述

攻击者常安装恶意 Windows 服务以实现持久化与提权（MITRE ATT&CK T1543.003——创建或修改系统进程：Windows 服务）。系统事件日志中的事件 ID 7045 记录每次新服务安装。本技能解析 .evtx 提取服务安装事件，标记可疑二进制路径（临时目录、PowerShell、cmd.exe、编码命令），并与已知攻击模式关联。


## 使用时机

- 调查需要猎杀异常服务安装的安全事件
- 为该领域构建检测规则或威胁猎杀查询
- SOC 分析师需要该分析类型的结构化流程
- 验证与相关攻击技术相关的安全监控覆盖

## 前置条件

- Python 3.9+，含 `python-evtx`、`lxml`
- Windows 系统事件日志（.evtx）文件
- 可选：实时系统事件日志访问
- 可选：Sysmon 日志以增强进程追踪

## 步骤

1. 解析 System.evtx 中的事件 ID 7045（已安装新服务）
2. 提取服务名、二进制路径、服务类型与运行账户
3. 标记可疑二进制路径（临时目录、编码命令）
4. 检测基于 PowerShell 的服务创建模式
5. 识别以 LocalSystem 运行且路径异常的服务
6. 与已知合法服务基线交叉比对
7. 生成含 MITRE ATT&CK T1543.003 映射的威胁猎杀报告

## 预期输出

- JSON 报告：列出所有新服务安装、风险分、可疑指标与修复建议
- 含二进制路径分析的服务安装事件时间线