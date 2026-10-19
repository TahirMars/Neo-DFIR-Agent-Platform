---
id: hunting-for-ntlm-relay-attacks
name: hunting-for-ntlm-relay-attacks
name_zh: 猎杀·NTLM·中继·攻击
description: 通过分析 Windows 事件 4624 中 Logon Type 3 且 NTLMSSP 认证、IP 与主机名不一致、Responder
  流量特征、SMB 签名状态及域内可疑认证模式，检测 NTLM 中继攻击。
domain: cybersecurity
subdomain: threat-hunting
tags:
- NTLM-relay
- Windows-events
- Event-4624
- NTLMSSP
- Responder
- SMB-signing
- credential-access
- T1557.001
- Active-Directory
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 猎杀 NTLM 中继攻击

## 概述

NTLM 中继攻击拦截并转发 NTLM 认证消息以未授权访问网络资源。攻击者常用 Responder 进行 LLMNR/NBT-NS 投毒，用 ntlmrelayx 进行中继。本技能通过查询 Windows 安全事件 4624（成功登录）中类型 3 网络登录且 NTLMSSP 认证、WorkstationName 与源 IpAddress 不匹配、单账户短时间对多主机认证，以及域内 SMB 签名配置审计来检测中继活动。


## 使用时机

- 调查需要猎杀 NTLM 中继的安全事件
- 为该领域构建检测规则或威胁猎杀查询
- SOC 分析师需要该分析类型的结构化流程
- 验证与相关攻击技术相关的安全监控覆盖

## 前置条件

- Python 3.9+，可访问 Windows 事件日志或导出日志
- Windows 安全审核日志已启用（事件 ID 4624、4625、5145）
- 网络访问以检查 SMB 签名状态

## 关键检测维度

1. **IP-主机名不一致** — 事件 4624 中 WorkstationName 解析结果与源 IpAddress 不符
2. **NTLMSSP 认证** — 已加域主机使用 NTLM 而非 Kerberos 的登录事件
3. **计算机账户中继** — 以 `$` 结尾的计算机账户来自意外 IP 的认证
4. **快速多主机认证** — 单账户数秒内对多台主机认证
5. **命名管道访问** — 事件 5145 访问 Spoolss、lsarpc、netlogon、samr 等管道
6. **SMB 签名未启用** — 主机未强制 SMB 签名，使中继成为可能

## 输出

JSON 报告：疑似中继事件、IP-主机名关联异常、SMB 签名审计结果及 MITRE ATT&CK T1557.001 映射。