---
id: analyzing-security-logs-with-splunk
name: analyzing-security-logs-with-splunk
name_zh: 分析·安全·日志·Splunk
description: 使用 Splunk Enterprise Security 和 SPL 进行日志关联、时间线重建和异常检测以调查安全事件。涵盖 Windows
  事件日志、防火墙日志、代理日志和身份验证数据分析。适用于涉及 Splunk 调查、SPL 查询、SIEM 日志分析、安全事件关联或基于日志的事件调查的场景。
domain: cybersecurity
subdomain: incident-response
tags:
- splunk
- SPL
- SIEM
- log-analysis
- security-monitoring
version: 1.0.0
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 分析·安全·日志·Splunk

## 使用时机
- 调查需要跨多个日志源关联的安全事件
- 使用已知的 TTP 和 IOC 寻找对手活动
- 为特定攻击模式建立检测规则
- 从不同的日志源重建事件时间线
- 分析身份验证异常、横向移动或数据泄露模式

**请勿使用**进行实时数据包级分析；使用 Wireshark 或 Zeek 进行完整的数据包捕获分析。

## 前置条件
- 安装了 Enterprise Security (ES) 应用程序的 Splunk Enterprise 或 Splunk Cloud
- 摄取的日志源：Windows 事件日志（通过 Splunk 通用转发器或 WEF）、防火墙、代理、DNS、EDR、电子邮件网关
- 为规范化字段名称配置的 Splunk CIM（通用信息模型）数据模型
- 中级或更高水平的 SPL 熟练程度
- Splunk 中具有“搜索”和“加速搜索”功能的基于角色的访问

## 工作流程
### 第 1 步：在 Splunk 中确定调查范围

根据事件分类数据定义搜索参数：```spl
| Set initial investigation scope
index=windows OR index=firewall OR index=proxy
  earliest="2025-11-14T00:00:00" latest="2025-11-16T00:00:00"
  (host="WKSTN-042" OR src_ip="10.1.5.42" OR user="jsmith")
| stats count by index, sourcetype, host
| sort -count
```此查询确定哪些日志源包含调查时间范围和受影响资产的相关数据。

### 第2步：分析身份验证事件

使用 Windows 安全事件日志调查可疑的身份验证模式：```spl
| Detect brute force and credential stuffing
index=windows sourcetype="WinEventLog:Security" EventCode=4625
  earliest=-24h
| stats count as failed_attempts, values(src_ip) as source_ips,
  dc(src_ip) as unique_sources by TargetUserName
| where failed_attempts > 10
| sort -failed_attempts

| Detect pass-the-hash (Logon Type 9 - NewCredentials)
index=windows sourcetype="WinEventLog:Security" EventCode=4624
  Logon_Type=9
| table _time, host, TargetUserName, src_ip, LogonProcessName

| Detect lateral movement via RDP
index=windows sourcetype="WinEventLog:Security" EventCode=4624
  Logon_Type=10
| stats count, values(host) as targets by TargetUserName, src_ip
| where count > 3
| sort -count
```### 第3步：跟踪进程执行

使用Sysmon日志重构进程执行链：```spl
| Process creation with parent chain (Sysmon Event ID 1)
index=sysmon EventCode=1 host="WKSTN-042"
  earliest="2025-11-15T14:00:00" latest="2025-11-15T15:00:00"
| table _time, ParentImage, ParentCommandLine, Image, CommandLine, User, Hashes
| sort _time

| Detect suspicious PowerShell execution
index=sysmon EventCode=1 Image="*\\powershell.exe"
  (CommandLine="*-enc*" OR CommandLine="*-encodedcommand*"
   OR CommandLine="*downloadstring*" OR CommandLine="*iex*")
| table _time, host, User, ParentImage, CommandLine
| sort _time

| Detect LSASS credential dumping
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
  GrantedAccess=0x1010
| table _time, host, SourceImage, SourceUser, GrantedAccess
```### 第4步：分析网络活动

将网络日志与端点事件关联起来：```spl
| Detect C2 beaconing pattern
index=proxy OR index=firewall dest_ip="185.220.101.42"
| timechart span=1m count by src_ip
| where count > 0

| Detect DNS tunneling (high query volume to single domain)
index=dns
| rex field=query "(?<subdomain>[^\.]+)\.(?<domain>[^\.]+\.[^\.]+)$"
| stats count, avg(len(query)) as avg_query_len by domain, src_ip
| where count > 500 AND avg_query_len > 40
| sort -count

| Detect large data transfers (potential exfiltration)
index=proxy action=allowed
| stats sum(bytes_out) as total_bytes by src_ip, dest_ip, dest_host
| eval total_MB=round(total_bytes/1024/1024,2)
| where total_MB > 100
| sort -total_MB
```### 第5步：建立事件时间表

跨所有日志源重建统一的时间线：```spl
| Unified incident timeline
index=windows OR index=sysmon OR index=proxy OR index=firewall
  (host="WKSTN-042" OR src_ip="10.1.5.42" OR user="jsmith")
  earliest="2025-11-15T14:00:00" latest="2025-11-15T16:00:00"
| eval event_summary=case(
    sourcetype=="WinEventLog:Security" AND EventCode==4624, "Logon: ".TargetUserName." from ".src_ip,
    sourcetype=="WinEventLog:Security" AND EventCode==4625, "Failed logon: ".TargetUserName,
    sourcetype=="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" AND EventCode==1,
      "Process: ".Image." by ".User,
    sourcetype=="proxy", "Web: ".http_method." ".url,
    1==1, sourcetype.": ".EventCode)
| table _time, sourcetype, host, event_summary
| sort _time
```### 第6步：创建检测规则

将调查结果转换为持续的 Splunk 相关性搜索：```spl
| Correlation search: PowerShell spawned by Office applications
index=sysmon EventCode=1
  Image="*\\powershell.exe"
  (ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe"
   OR ParentImage="*\\outlook.exe")
| eval severity="high"
| eval mitre_technique="T1059.001"
| collect index=notable_events
```## 关键概念

|术语 |定义|
|------|------------|
| **SPL（搜索处理语言）** | Splunk 用于搜索、过滤、转换和可视化机器数据的查询语言 |
| **CIM（通用信息模型）** | Splunk 的字段规范化标准，将供应商特定的字段名称映射到跨源查询的通用名称 |
| **值得注意的事件** | Splunk Enterprise Security 中的一个事件根据相关性搜索匹配标记为供分析师审查 |
| **数据模型** | Splunk 中索引数据的结构化表示可实现加速搜索和基于数据透视的分析 |
| **来源类型** | Splunk 中的分类标签，定义特定日志类型的格式和解析规则 |
| **相关性搜索** | 计划的 Splunk 搜索连续运行并在满足条件时生成显着事件 |
| **时间表** | SPL 命令可创建时间序列可视化以识别模式、异常和趋势 |

## 工具和系统

- **Splunk Enterprise Security (ES)**：高级 SIEM 应用程序，提供关联搜索、基于风险的警报和调查工作台
- **Splunk SOAR**：与 Splunk ES 集成的编排平台，用于自动响应手册
- **Sysmon**：Microsoft 系统监控工具，提供纳入 Splunk 的详细进程、网络和文件更改遥测数据
- **Splunk 攻击分析器**：自动威胁分析，引爆可疑文件和 URL，将结果输入 Splunk
- **SOC 的 BOSS (BOTS)**：用于练习事件调查 SPL 查询的 SANS/Splunk 训练数据集

## 常见场景

### 场景：调查导致帐户被盗的撞库行为

**上下文**：安全操作会收到在 30 分钟内从地理位置分散的 IP 地址多次成功登录单个帐户的警报。

**方法**：
1. 查询受影响账户的事件ID 4624，映射所有登录来源和时间
2. 使用 Splunk 查找表将登录 IP 与威胁情报源关联起来
3. 检查代理日志中经过身份验证的会话是否存在可疑活动
4. 搜索从受感染帐户的横向移动（事件 ID 4624 类型 3 到其他主机）
5. 建立一个时间表，显示撞库尝试、成功登录和泄露后活动
6. 创建相关性搜索以检测其他帐户上的相似模式

**陷阱**：
- 仅搜索最近24小时，此时撞库事件可能已发生数周
- 不检查 VPN 日志，这些日志可能显示同一帐户在不可能的旅行距离进行身份验证
- 未能规范不同时区日志源的时间戳

## 输出格式

```
SPLUNK INVESTIGATION REPORT
============================
Incident:        INC-2025-1547
Analyst:         [Name]
Investigation Period: 2025-11-14 00:00 UTC - 2025-11-16 00:00 UTC

SEARCH SCOPE
Indexes:         windows, sysmon, proxy, firewall, dns
Hosts:           WKSTN-042, SRV-FILE01
Users:           jsmith, svc-backup
Source IPs:      10.1.5.42, 10.1.10.15

KEY FINDINGS
1. [timestamp] - 初始入侵通过钓鱼（Sysmon 事件 1）
2. [timestamp] - 建立 C2（代理日志，检测到信标模式）
3. [timestamp] - 凭证窃取（Sysmon 事件 10，LSASS 访问）
4. [timestamp] - 向 SRV-FILE01 横向移动（事件 4624 类型 3）
5. [timestamp] - 数据暂存和泄露（代理 bytes_out 异常）

SPL QUERIES USED
[带描述的关键查询编号列表]

DETECTION GAPS IDENTIFIED
- SRV-FILE01 未部署 Sysmon（盲点）
- 代理日志缺少 C2 域的 SSL 检查
- 未启用 PowerShell ScriptBlock 日志记录

RECOMMENDED DETECTIONS
1. 针对 Office 启动的 PowerShell 的关联搜索
2. LSASS 访问模式的阈值警报
3. 信标间隔网络流量的行为规则
```