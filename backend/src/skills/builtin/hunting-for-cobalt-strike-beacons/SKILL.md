---
name: hunting-for-cobalt-strike-beacons
id: hunting-for-cobalt-strike-beacons
description: 使用默认 TLS 证书特征（序列号 8BB00EE）、JA3/JA3S/JARM 指纹、HTTP C2 配置模式匹配、信标抖动分析与命名管道检测，结合
  Zeek、Suricata 与 Python PCAP 分析识别 Cobalt Strike 信标网络活动。
domain: cybersecurity
subdomain: threat-hunting
tags:
- cobalt-strike
- beacon
- threat-hunting
- c2
- zeek
- suricata
- ja3
- jarm
- network-forensics
version: '1.0'
author: mahipal
license: Apache-2.0
neo_agents:
- forensic
- general_chat
---

# 狩猎 Cobalt Strike 信标

## 概述

Cobalt Strike 是红队与威胁行为体最常用的命令与控制框架。其主要载荷 Beacon 通过可配置的 HTTP/HTTPS/DNS 与团队服务器通信，可模仿合法流量。但默认配置与行为模式仍可通过 TLS 证书分析（默认序列 8BB00EE）、JA3/JA3S 指纹、信标间隔抖动分析与 HTTP malleable 配置模式匹配进行检测。本技能介绍如何利用 Zeek 网络日志、Suricata IDS 规则与基于 Python 的 PCAP 分析在网络流量中识别信标回连。

## 何时使用

- 需要狩猎 Cobalt Strike 信标相关安全事件时
- 为该领域构建检测规则或威胁狩猎查询时
- SOC 分析师需要该分析类型的结构化流程时
- 验证与相关攻击技术的安全监控覆盖时

## 先决条件

- Zeek 6.0+，已安装 JA3 与 HASSH 相关包
- Suricata 7.0+，使用 Emerging Threats 规则集
- Python 3.9+，安装 scapy 与 dpkt
- 网络流量捕获（PCAP）或实时 Zeek 日志
- RITA（Real Intelligence Threat Analytics）用于信标评分
- 含已知 Cobalt Strike IOC 的威胁情报源

## 步骤

### 步骤 1：TLS 证书分析
在 Zeek ssl.log 中通过 JA3S 指纹、证书序列号与 JARM 指纹检测默认 Cobalt Strike 证书。

### 步骤 2：信标间隔分析
分析连接时序模式，识别带可配置抖动的规律回连间隔，符合信标行为特征。

### 步骤 3：HTTP 配置检测
将 HTTP 请求模式（URI 路径、头、User-Agent）与已知 malleable C2 配置匹配。

### 步骤 4：关联与评分
将 TLS、时序与 HTTP 配置等多指标合并为综合信标置信度分。

## 预期输出

JSON 报告，包含检出的信标候选、置信度分、TLS 指纹、时序分析、HTTP 配置匹配与建议响应动作。