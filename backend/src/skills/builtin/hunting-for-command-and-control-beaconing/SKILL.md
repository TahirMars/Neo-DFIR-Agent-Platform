---
name: hunting-for-command-and-control-beaconing
id: hunting-for-command-and-control-beaconing
description: 使用频率分析、抖动检测与域名信誉在网络流量中检测 C2 信标模式，识别与对手基础设施通信的受控端点。
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- mitre-attack
- c2
- beaconing
- network-analysis
- proactive-detection
version: '1.0'
author: mahipal
license: Apache-2.0
neo_agents:
- forensic
- general_chat
---

# 狩猎命令与控制（C2）信标

## 何时使用

- 在网络中主动狩猎受控系统时
- 威胁情报表明 C2 框架针对本行业时
- 调查对可疑域名的周期性出站连接时
- 事件响应中需识别活跃 C2 信道时
- DNS 查询日志显示对特定域名的异常模式时

## 先决条件

- 含完整 URL 与时序数据的网络代理/防火墙日志
- DNS 查询日志（被动 DNS、DNS 服务器日志或 Sysmon 事件 ID 22）
- Zeek/Bro 连接日志或 NetFlow 数据
- 具备统计分析能力的 SIEM（Splunk、Elastic）
- 用于域名/IP 信誉的威胁情报源

## 工作流程

1. **识别信标特征**：定义何为信标（规律间隔、小载荷、一致目标、抖动模式）。
2. **采集网络遥测**：汇总代理日志、DNS 查询与连接元数据用于分析。
3. **应用频率分析**：用统计方法（标准差、变异系数）识别规律间隔连接。
4. **过滤已知良性流量**：排除合法周期性流量（Windows 更新、杀软更新、心跳服务、NTP）。
5. **分析域名/IP 信誉**：将信标目标对照威胁情报、WHOIS 与证书透明度日志。
6. **调查终端上下文**：将信标活动与源端点上的进程创建、用户上下文与文件系统变更关联。
7. **确认与响应**：验证 C2 活动，阻断通信并启动事件响应。

## 关键概念

| 概念 | 说明 |
|---------|-------------|
| T1071 | 应用层协议（HTTP/HTTPS/DNS C2） |
| T1071.001 | Web 协议（HTTP/S 信标） |
| T1071.004 | DNS（DNS 隧道 C2） |
| T1573 | 加密信道 |
| T1572 | 协议隧道 |
| T1568 | 动态解析（DGA、fast-flux） |
| T1132 | C2 中的数据编码 |
| T1095 | 非应用层协议 |
| 信标间隔 | C2 签到之间的时间 |
| 抖动 | 信标间隔上的随机变化 |
| DGA | 域名生成算法 |
| Fast-Flux | 快速变化的 DNS 解析 |

## 工具与系统

| 工具 | 用途 |
|------|---------|
| RITA（Real Intelligence Threat Analytics） | 在 Zeek 日志中自动检测信标 |
| Splunk | 基于 SPL 的统计信标分析 |
| Elastic Security | 基于 ML 的信标异常检测 |
| Zeek/Bro | 网络连接元数据采集 |
| Suricata | 含 JA3/JA4 指纹的网络 IDS |
| VirusTotal | 域名与 IP 信誉查询 |
| PassiveDNS | 历史 DNS 解析数据 |
| Flare | C2 配置检测 |

## 常见场景

1. **Cobalt Strike 信标**：HTTP/HTTPS 信标，可配置睡眠与抖动及 malleable C2 配置。
2. **DNS 隧道 C2**：通过编码 DNS TXT/CNAME 查询向攻击者控制域名外带数据并接收指令。
3. **HTTPS 上的 Sliver C2**：现代 C2 框架，HTTPS 信标间隔可配置并支持域名前置。
4. **基于 DGA 的 C2**：恶意软件每日生成随机域名，攻击者提前注册即将使用的域名用于 C2。
5. **合法服务滥用**：经 Azure、AWS、Slack、Discord、Telegram 等云服务的 C2。

## 输出格式

```
Hunt ID: TH-C2-[DATE]-[SEQ]
Source IP: [Internal IP]
Source Host: [Hostname]
Destination: [Domain/IP]
Protocol: [HTTP/HTTPS/DNS/Custom]
Beacon Interval: [Average seconds]
Jitter: [Percentage]
Connection Count: [Total connections]
Data Volume: [Bytes sent/received]
First Seen: [Timestamp]
Last Seen: [Timestamp]
Domain Age: [Days]
TI Match: [Yes/No - source]
Risk Level: [Critical/High/Medium/Low]
```