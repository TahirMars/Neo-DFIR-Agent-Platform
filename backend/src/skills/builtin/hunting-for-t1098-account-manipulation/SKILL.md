---
id: hunting-for-t1098-account-manipulation
name: hunting-for-t1098-account-manipulation
name_zh: 猎杀·T1098·账户·操纵
description: 使用 Windows 安全事件日志猎杀 MITRE ATT&CK T1098 账户操纵，包括影子管理员创建、SID History 注入、组成员变更与凭据修改。
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- mitre-attack
- t1098
- account-manipulation
- active-directory
- persistence
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 猎杀 T1098 账户操纵

## 概述

MITRE ATT&CK T1098（账户操纵）涵盖对手为维持或扩大对已沦陷账户访问而采取的动作，包括添加凭据、修改组成员、SID History 注入与创建影子管理员。本技能通过 Windows 安全事件日志（事件 ID 4738、4728、4732、4756、4670、5136）检测这些技术，关联组成员变更与提权指标，并识别异常账户修改模式。


## 使用时机

- 调查需要猎杀 T1098 账户操纵的安全事件
- 为该领域构建检测规则或威胁猎杀查询
- SOC 分析师需要该分析类型的结构化流程
- 验证与相关攻击技术相关的安全监控覆盖

## 前置条件

- Windows 安全事件日志（EVTX）或 SIEM 访问
- Python 3.9+，含 `python-evtx`、`lxml`
- 了解 Active Directory 组结构与 SID 体系
- 熟悉 MITRE ATT&CK T1098 子技术

## 步骤

### 第 1 步：解析账户修改事件
提取事件 ID 4738（用户账户已更改）、4728/4732/4756（已添加到安全组）、5136（目录服务对象已修改）。

### 第 2 步：检测特权组变更
标记加入 Domain Admins、Enterprise Admins、Schema Admins、Administrators、Backup Operators 等组的情况。

### 第 3 步：识别影子管理员指标
检测获得 AdminSDHolder 保护、直接特权分配或 SID History 注入的账户。

### 第 4 步：与攻击时间线关联
将账户变更与认证事件交叉引用，定位初始沦陷与持久化建立时间。

## 预期输出

JSON 报告：检出的账户操纵事件、特权组变更、影子管理员指标与时间线关联。