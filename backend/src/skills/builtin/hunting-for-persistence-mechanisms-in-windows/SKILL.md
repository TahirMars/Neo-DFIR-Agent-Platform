---
id: hunting-for-persistence-mechanisms-in-windows
name: hunting-for-persistence-mechanisms-in-windows
name_zh: 猎杀·Windows·持久化·机制
description: 在 Windows 端点上系统性猎杀对手持久化机制，涵盖注册表、服务、启动文件夹与 WMI 订阅等。
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- mitre-attack
- persistence
- windows
- registry
- siem
- proactive-detection
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 猎杀 Windows 中的持久化机制

## 使用时机

- 定期主动猎杀休眠后门
- 事件后识别攻击者植入的全部持久化
- 调查异常服务、计划任务或启动项
- 威胁情报描述野外新持久化技术时
- 安全态势评估中发现未授权持久软件

## 前置条件

- Sysmon 启用事件 ID 12/13/14（注册表）、19/20/21（WMI）、1（进程创建）
- Windows 安全事件转发 4697（服务安装）、4698（计划任务）
- 具备注册表与文件监控能力的 EDR
- 已启用 PowerShell 脚本块日志（事件 ID 4104）
- Autoruns 或等效的合法持久化项基线

## 工作流程

1. **枚举已知持久化位置**：建立 Windows 持久化点全面列表（Run 键、服务、计划任务、WMI、启动文件夹、DLL 搜索顺序劫持、COM 劫持、AppInit DLL、IFEO 等）。
2. **采集端点数据**：通过 EDR、Sysmon 或 Velociraptor 从全环境端点采集当前持久化工件。
3. **建立合法持久化基线**：与已知良好基线比对（Autoruns 快照、GPO 下发、SCCM 配置）。
4. **识别异常**：标记持久化位置中新增、未签名或未知且偏离基线的项。
5. **调查可疑项**：逐项检查指向的二进制、数字签名、哈希与创建时间戳。
6. **与进程活动关联**：将持久化项与进程执行、网络活动与登录事件关联。
7. **记录与清除**：记录发现、清除恶意持久化并更新检测规则。

## 关键概念

| 概念 | 说明 |
|---------|-------------|
| T1547.001 | 注册表 Run 键 / 启动文件夹 |
| T1543.003 | Windows 服务（创建或修改） |
| T1053.005 | 计划任务 |
| T1546.003 | WMI 事件订阅 |
| T1546.015 | 组件对象模型（COM）劫持 |
| T1546.012 | 映像文件执行选项（IFEO）注入 |
| T1546.010 | AppInit DLL |
| T1547.004 | Winlogon 辅助 DLL |
| T1547.005 | 安全支持提供程序 |
| T1574.001 | DLL 搜索顺序劫持 |
| TA0003 | 持久化战术 |
| Autoruns | Sysinternals 持久化枚举工具 |

## 工具与系统

| 工具 | 用途 |
|------|---------|
| Sysinternals Autoruns | 全面持久化枚举 |
| Velociraptor | 跨端点持久化工件采集 |
| CrowdStrike Falcon | 实时持久化监控 |
| Sysmon | 注册表与 WMI 事件 |
| OSQuery | 基于 SQL 的持久化查询 |
| RECmd | 注册表取证分析 |
| Splunk | 持久化事件 SIEM 关联 |

## 常见场景

1. **注册表 Run 键后门**：恶意软件在 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` 添加指向 `%APPDATA%` 载荷的项。
2. **WMI 事件订阅**：对手创建 WMI 消费者/过滤器对，在系统启动时执行 PowerShell。
3. **恶意服务**：攻击者用 `sc create` 创建指向后门二进制 Windows 服务。
4. **COM 对象劫持**：合法 COM CLSID 的 InprocServer32 路径被替换为恶意 DLL。
5. **IFEO 调试器注入**：IFEO 键设置调试器指向植入体，劫持常用工具启动。

## 输出格式

```
猎杀 ID: TH-PERSIST-[DATE]-[SEQ]
持久化类型: [注册表/服务/任务/WMI/COM/其他]
MITRE 技术: T1547.xxx / T1543.xxx / T1053.xxx
位置: [完整注册表键 / 服务名 / 任务路径]
值: [二进制路径 / 命令行]
主机: [受影响端点]
已签名: [是/否]
哈希: [SHA256]
创建时间: [时间戳]
风险级别: [严重/高/中/低]
结论: [恶意/可疑/良性]
```