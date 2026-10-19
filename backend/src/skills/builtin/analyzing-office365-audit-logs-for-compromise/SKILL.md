---
id: analyzing-office365-audit-logs-for-compromise
name: analyzing-office365-audit-logs-for-compromise
name_zh: 分析·Office 365·审计·日志·失陷
description: 通过 Microsoft Graph API 解析 Office 365 统一审核日志，检测邮件转发规则创建、收件箱委派、可疑 OAuth
  应用授权等账户入侵指标。
domain: cybersecurity
subdomain: cloud-security
tags:
- Office365
- Microsoft-Graph
- audit-logs
- email-compromise
- inbox-rules
- OAuth
- BEC
version: '1.0'
author: mahipal
license: Apache-2.0
neo_agents:
- forensic
- general_chat
---

# 分析 Office 365 审核日志以检测入侵

## 概述
商务电子邮件入侵（BEC）攻击通常会在 Office 365 审核日志中留下痕迹：可疑的收件箱规则创建、邮件转发到外部地址、邮箱委派变更以及未经授权的 OAuth 应用程序同意授权。此技能使用 Microsoft Graph API 查询统一审核日志，枚举邮箱中的收件箱规则，检测转发配置，并识别入侵账户的指标。

## 使用时机
- 在调查需要分析 office365 审核日志的入侵事件时
- 在构建此领域的检测规则或威胁狩猎查询时
- 当 SOC 分析师需要此类分析的结构化流程时
- 在验证相关攻击技术的安全监控覆盖范围时

## 前置条件
- Azure AD 应用注册，具有 `AuditLog.Read.All`、`MailboxSettings.Read`、`Mail.Read`（应用权限）
- Python 3.9+ 环境，安装 `msal`、`requests` 库
- 身份验证用的客户端密钥或证书
- 全局读者或安全读者角色

## 步骤

1. 使用 MSAL 客户端凭据流对 Microsoft Graph 进行身份验证
2. 查询统一审核日志中的可疑操作（Set-Mailbox, New-InboxRule）
3. 跨邮箱枚举收件箱规则并标记转发规则
4. 检测邮箱委派变更（Add-MailboxPermission）
5. 识别对可疑应用程序的 OAuth 同意授权
6. 从审核日志中检查可疑的登录模式
7. 生成包含时间线的入侵指标报告

## 预期输出

- JSON 报告，列出转发规则、委派变更、OAuth 授权及可疑审核事件，并附风险评分
- 包含受影响邮箱的入侵指标时间线