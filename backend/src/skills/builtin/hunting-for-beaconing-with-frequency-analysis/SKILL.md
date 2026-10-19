---
name: hunting-for-beaconing-with-frequency-analysis
id: hunting-for-beaconing-with-frequency-analysis
description: 通过对网络流量应用统计频率分析、抖动计算与变异系数评分，识别受控端点周期性回连的命令与控制（C2）信标模式。
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- beaconing
- c2-detection
- frequency-analysis
- network-traffic
- RITA
- jitter-detection
- mitre-t1071
version: '1.0'
author: mahipal
license: Apache-2.0
neo_agents:
- forensic
- general_chat
---

# 基于频率分析狩猎信标（Beaconing）

## 何时使用

- 主动搜寻回连 C2 基础设施的受控端点时
- 威胁情报表明活跃 C2 框架针对本行业时
- 网络日志出现对陌生目标的周期性出站连接时
- 紫队演练验证 C2 检测能力时
- 调查潜在入侵并需识别活跃 C2 信道时

## 先决条件

- 带时间戳与目标数据的网络代理/防火墙日志（至少 24 小时）
- Zeek conn.log、dns.log、ssl.log 或等效 NetFlow/IPFIX 数据
- 具备统计分析能力的 SIEM（Splunk、Elastic、Microsoft Sentinel）
- RITA（Real Intelligence Threat Analytics）或 AC-Hunter 用于自动化信标分析
- 用于域名/IP 信誉富集的情报源

## 工作流程

1. **定义信标参数**：建立检测阈值——变异系数（CV）低于 0.20 表示强周期性；24 小时内至少 50 次连接；平均间隔在 30 秒至 24 小时之间。
2. **采集网络遥测**：将代理日志、DNS 查询、防火墙连接日志与 Zeek 元数据汇总到分析平台。
3. **计算连接间隔**：对每个源-目的对，计算连续连接间时间差，得出平均间隔、标准差与 CV。
4. **应用抖动分析**：高级 C2（如 Cobalt Strike）在信标间隔中加入抖动（随机性）。Sunburst 后门约每 15 分钟 ±90 秒回连。分析抖动模式以检测随机化信标。
5. **过滤合法周期性流量**：排除已知良性周期性源：Windows 更新、杀软定义更新、NTP、SaaS 心跳、CDN 健康检查等。
6. **分析数据量一致性**：C2 心跳包通常载荷大小一致。计算每次连接传输字节的 CV——低方差往往表示自动化通信。
7. **威胁情报富集**：将识别出的信标目标对照 VirusTotal、WHOIS（标记注册不足 30 天的域名）、证书透明度与被动 DNS 历史。
8. **与终端遥测关联**：通过 DHCP 日志将信源源 IP 映射到主机名，再与进程创建（Sysmon 事件 ID 1、3）关联以定位责任进程。
9. **评分与排序**：根据 CV、域名年龄、TI 匹配、数据量一致性与可疑端口使用情况分配风险分。高置信发现应升级。

## 关键概念

| 概念 | 说明 |
|---------|-------------|
| T1071.001 | 应用层协议：Web 协议——HTTP/HTTPS 信标 |
| T1071.004 | 应用层协议：DNS——基于 DNS 的 C2 隧道 |
| T1573 | 加密信道——TLS/SSL 加密的 C2 |
| T1568.002 | 动态解析：域名生成算法（DGA） |
| 变异系数 | 标准差除以均值；低于 0.20 表示周期性 |
| 抖动 | 为规避检测在信标间隔上加入的随机变化 |
| RITA 信标分 | 由连接规律性、数据量一致性与连接次数组成的综合分 |
| JA3/JA4 指纹 | TLS 客户端指纹，用于识别 C2 框架特征 |
| Fast-Flux DNS | 快速变化的 DNS 解析，用于保护 C2 基础设施 |

## 工具与系统

| 工具 | 用途 |
|------|---------|
| RITA（Real Intelligence Threat Analytics） | 从 Zeek 日志自动信标评分 |
| AC-Hunter | 含信标检测的商业威胁狩猎平台 |
| Splunk | 基于 SPL 的统计信标分析（含 streamstats） |
| Elastic Security | 针对周期性网络行为的 ML 异常检测 |
| Zeek | 网络元数据采集（conn、dns、ssl 日志） |
| Suricata | 网络 IDS，提取 JA3/JA4 TLS 指纹 |
| FLARE | C2 配置与信标模式检测 |
| VirusTotal | 域名与 IP 信誉富集 |

## 检测查询

### Splunk——HTTP/S 信标频率分析
```spl
index=proxy OR index=firewall
| where NOT match(dest, "(?i)(microsoft|google|amazonaws|cloudflare|akamai)")
| bin _time span=1s
| stats count by src_ip dest _time
| streamstats current=f last(_time) as prev_time by src_ip dest
| eval interval=_time-prev_time
| stats count avg(interval) as avg_interval stdev(interval) as stdev_interval
  min(interval) as min_interval max(interval) as max_interval by src_ip dest
| where count > 50
| eval cv=stdev_interval/avg_interval
| where cv < 0.20 AND avg_interval > 30 AND avg_interval < 86400
| sort cv
| table src_ip dest count avg_interval stdev_interval cv
```

### KQL——Microsoft Sentinel 信标检测
```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPType == "Public"
| summarize ConnectionTimes=make_list(Timestamp), Count=count() by DeviceName, RemoteIP, RemoteUrl
| where Count > 50
| extend Intervals = array_sort_asc(ConnectionTimes)
| mv-apply Intervals on (
    extend NextTime = next(Intervals)
    | where isnotempty(NextTime)
    | extend IntervalSec = datetime_diff('second', NextTime, Intervals)
    | summarize AvgInterval=avg(IntervalSec), StdDev=stdev(IntervalSec)
)
| extend CV = StdDev / AvgInterval
| where CV < 0.2 and AvgInterval > 30
| sort by CV asc
```

### Sigma 规则——信标模式检测
```yaml
title: Potential C2 Beaconing Pattern Detected
status: experimental
logsource:
    category: proxy
detection:
    selection:
        dst_ip|cidr: '!10.0.0.0/8'
    timeframe: 24h
    condition: selection | count(dst) by src_ip > 50
level: medium
tags:
    - attack.command_and_control
    - attack.t1071.001
```

## 常见场景

1. **Cobalt Strike 信标**：默认 60 秒间隔，HTTPS 上可配置 0–50% 抖动。Malleable C2 配置可模仿合法流量。
2. **Sunburst/SUNSPOT**：12–14 天休眠后约每 12–14 分钟回连并带随机抖动，旨在规避频率分析。
3. **DNS 隧道 C2**：通过 DNS TXT/CNAME 查询向攻击者控制域名外带编码数据，可通过高子域熵与查询量检测。
4. **Sliver C2**：现代 C2 框架，支持 HTTPS、mTLS、WireGuard，信标间隔可配置且内置抖动。
5. **合法服务滥用**：经 Slack、Discord、Telegram 或云存储 API 的 C2，使基于目标的过滤失效。

## 输出格式

```
Hunt ID: TH-BEACON-[DATE]-[SEQ]
Source IP: [Internal IP]
Source Host: [Hostname from DHCP/DNS]
Destination: [Domain/IP]
Protocol: [HTTP/HTTPS/DNS]
Beacon Interval: [Average seconds]
Jitter Estimate: [Percentage]
Coefficient of Variation: [CV value]
Connection Count: [Total connections in window]
Data Size CV: [Payload consistency metric]
Domain Age: [Days since registration]
TI Match: [Yes/No -- source]
Risk Score: [0-100]
Risk Level: [Critical/High/Medium/Low]
Indicators: [List of triggered risk factors]
```