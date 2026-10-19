---
id: hunting-for-dns-based-persistence
name: hunting-for-dns-based-persistence
name_zh: 威胁狩猎·DNS·基于·持久化
description: 使用被动 DNS 库、SecurityTrails API 与 DNS 审核日志分析，猎杀 DNS 劫持、悬空 CNAME、通配符 DNS
  滥用与未授权区域修改等基于 DNS 的持久化机制。
domain: cybersecurity
subdomain: threat-hunting
tags:
- dns
- persistence
- threat-hunting
- passive-dns
- dns-hijacking
- subdomain-takeover
- securitytrails
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 威胁狩猎·DNS·基于·持久化

## 概述

攻击者通过劫持 DNS 记录、创建未授权子域、滥用通配符 DNS 或修改 NS 委派，将流量导向其控制的基础设施，从而建立 DNS 持久化。此类技术可在凭据轮换、端点重装与传统处置后仍然存在，因 DNS 变更独立于沦陷主机。检测需被动 DNS 历史分析、区域文件审核与未授权记录变更监控。本技能涵盖使用 SecurityTrails 被动 DNS API、Route53/Azure DNS/Cloudflare 等 DNS 审核日志及区域传送（AXFR）分析的猎杀方法。


## 使用时机

- 调查需要猎杀基于 DNS 的持久化的安全事件
- 为该领域构建检测规则或威胁猎杀查询
- SOC 分析师需要该分析类型的结构化流程
- 验证与相关攻击技术相关的安全监控覆盖

## 前置条件

- SecurityTrails API 密钥（免费层约 50 次查询/月）
- DNS 提供商审核日志访问（Route53、Azure DNS、Cloudflare 或本地 DNS）
- Python 3.9+ 与 requests 库
- 内部区域的 DNS 区域文件访问或 AXFR 能力
- 用于比对的历史 DNS 基线

## 步骤

### 第 1 步：DNS 记录基线
导出当前 DNS 区域记录，为所有授权的 A、AAAA、CNAME、MX、NS、TXT 建立基线。

### 第 2 步：查询被动 DNS 历史
使用 SecurityTrails API 获取历史 DNS 记录，识别未授权变更、新子域及指向已下线服务的 CNAME（悬空 CNAME）。

### 第 3 步：检测异常
将当前记录与基线比对，发现未授权修改、解析所有子域的通配符、NS 委派变更与 MX 劫持。

### 第 4 步：调查发现
将 DNS 异常与威胁情报关联，检查解析目标是否指向已知恶意基础设施，并验证记录归属。

## 预期输出

JSON 报告：列出 DNS 异常，含记录类型、历史变更、风险严重度及每项发现的修复建议。