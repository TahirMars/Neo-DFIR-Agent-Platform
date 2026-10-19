---
id: hunting-for-domain-fronting-c2-traffic
name: hunting-for-domain-fronting-c2-traffic
name_zh: 威胁狩猎·域名·前置代理·C2·流量
description: 通过解析代理日志中 SNI 与 HTTP Host 头不一致及使用 pyOpenSSL 检查 TLS 证书差异，检测域名前置（domain
  fronting）C2 流量（MITRE T1090.004）。
domain: cybersecurity
subdomain: threat-hunting
tags:
- domain-fronting
- c2-detection
- tls-inspection
- proxy-logs
- pyopenssl
- threat-hunting
- network-security
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 威胁狩猎·域名·前置代理·C2·流量

## 概述

域名前置（MITRE ATT&CK T1090.004）指攻击者在 TLS SNI 与 HTTP Host 头使用不同域名，将 C2 流量伪装成指向合法 CDN 托管域名的流量。本技能通过解析代理/安全 Web 网关日志中的 SNI 与 Host 不匹配、分析 TLS 证书以识别 CDN、标记 SNI 指向高信誉域而 Host 指向攻击者控制域的连接，并与已知 CDN IP 段关联完成检测。


## 使用时机

- 调查需要猎杀域名前置 C2 流量的安全事件
- 为该领域构建检测规则或威胁猎杀查询
- SOC 分析师需要该分析类型的结构化流程
- 验证与相关攻击技术相关的安全监控覆盖

## 前置条件

- 含 SNI 与 Host 头字段的 Web 代理或安全 Web 网关日志
- Python 3.8+，含 pyOpenSSL 与 cryptography
- 代理启用 TLS 检查以可见 Host 头
- CDN 提供商 IP 段列表（CloudFront、Azure CDN、Cloudflare）

## 步骤

1. 解析同时含 SNI 与 Host 头的代理日志连接
2. 比对 SNI 域名与 HTTP Host 头是否不一致
3. 使用 pyOpenSSL 提取 TLS 证书 Subject 与 SAN
4. 通过证书颁发者与 IP 段识别 CDN 托管连接
5. 在 CDN IP 上对 SNI 与 Host 不一致的情况标记为高置信域名前置
6. 根据域名信誉差异对告警评分
7. 生成含网络流上下文的检测报告

## 预期输出

JSON 报告：检出域名前置指标、SNI-Host 对、证书详情、CDN 提供商识别、置信度评分及 MITRE ATT&CK 技术映射。