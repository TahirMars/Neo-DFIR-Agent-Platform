---
id: hunting-for-dcsync-attacks
name: hunting-for-dcsync-attacks
name_zh: 威胁狩猎·DCSync·攻击
description: 通过分析 Windows 事件 ID 4662，检测非域控账户对 DS-Replication-Get-Changes 等未授权域复制请求，以发现
  DCSync 攻击。
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- dcsync
- active-directory
- credential-access
- t1003.006
- mimikatz
- windows
- dfir
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 威胁狩猎·DCSync·攻击

## 使用时机

- 猎杀 DCSync 凭据窃取（MITRE ATT&CK T1003.006）
- 环境中发现 Mimikatz 或类似工具之后
- 涉及 Active Directory 沦陷的事件响应
- 监控未授权的域复制请求
- 紫队演练中测试 AD 攻击检测

## 前置条件

- 已启用 Windows 安全事件日志转发（事件 ID 4662）
- 通过组策略启用「审核目录服务访问」
- 在域对象上配置 Domain Computers SACL 以检测计算机账户
- 已接入 Windows 事件的 SIEM（Splunk、Elastic、Sentinel）
- 了解合法域控账户与复制伙伴

## 工作流程

1. **启用审核**：确保在域控上启用「审核目录服务访问」。
2. **收集事件**：收集 AccessMask 为 0x100（控制访问）的 Windows 事件 ID 4662。
3. **过滤复制 GUID**：检索 DS-Replication-Get-Changes 与 DS-Replication-Get-Changes-All。
4. **识别非 DC 来源**：标记 SubjectUserName 非域控计算机账户的事件。
5. **与网络关联**：将源 IP 与已知 DC 地址交叉比对。
6. **验证发现**：排除合法复制工具（Azure AD Connect、SCCM 等）。
7. **响应**：禁用沦陷账户、重置 krbtgt、调查横向移动。

## 关键概念

| 概念 | 说明 |
|---------|-------------|
| DCSync | 滥用 AD 复制协议提取密码哈希的技术 |
| 事件 ID 4662 | 目录服务访问审核事件 |
| DS-Replication-Get-Changes | GUID 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 |
| DS-Replication-Get-Changes-All | GUID 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 |
| AccessMask 0x100 | 表示扩展权限校验的控制访问权限 |
| T1003.006 | 操作系统凭据转储：DCSync |

## 工具与系统

| 工具 | 用途 |
|------|---------|
| Windows 事件查看器 | 直接分析事件日志 |
| Splunk | 事件 4662 的 SIEM 关联 |
| Elastic Security | DCSync 模式检测规则 |
| Mimikatz lsadump::dcsync | 执行 DCSync 的攻击工具 |
| Impacket secretsdump.py | 基于 Python 的 DCSync 实现 |
| BloodHound | 识别具备复制权限的账户 |

## 输出格式

```
Hunt ID: TH-DCSYNC-[DATE]-[SEQ]
Technique: T1003.006
Domain Controller: [DC hostname]
Subject Account: [Account performing replication]
Source IP: [Non-DC IP address]
GUID Accessed: [Replication GUID]
Risk Level: [Critical/High/Medium/Low]
Recommended Action: [Disable account, reset krbtgt, investigate]
```