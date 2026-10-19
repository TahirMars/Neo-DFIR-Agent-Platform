---
id: analyzing-network-traffic-with-wireshark
name: analyzing-network-traffic-with-wireshark
name_zh: 分析·网络·流量·Wireshark
description: 使用 Wireshark 与 tshark 捕获并分析网络数据包，以识别恶意流量模式、诊断协议问题、提取工件，并在授权网段上支持事件响应调查。
domain: cybersecurity
subdomain: network-security
tags:
- network-security
- wireshark
- packet-analysis
- traffic-analysis
- pcap
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 分析·网络·流量·Wireshark

## 使用时机

- 通过数据包级证据调查可疑入侵（C2、数据外泄、横向移动）
- 诊断网络性能问题（重传、分片、DNS 解析失败等）
- 从沙箱或隔离主机抓包分析恶意软件通信模式
- 验证防火墙与 IDS 规则，确认网段内实际穿越的流量
- 从捕获会话中提取文件、凭据或失陷指标（IOC）

**请勿用于**未经授权的网络抓包、无法律授权的通信截获，或作为生产环境完整 SIEM 的替代方案。

## 前置条件

- 已安装 Wireshark 4.0+ 与 tshark 命令行工具
- 实时抓包需 root/sudo 或加入 `wireshark` 用户组
- 可访问受监控网段的网络接口（物理网卡、SPAN、分流器）
- 足够磁盘空间保存抓包（繁忙千兆链路可粗略按每分钟约 1 GB 估算）
- 熟悉数据包级的 TCP/IP、HTTP、DNS、TLS、SMB

## 工作流程

### 第 1 步：配置捕获环境

设置捕获接口与过滤器以聚焦相关流量：```bash
# List available interfaces
tshark -D

# Start capture on eth0 with a capture filter to limit scope
tshark -i eth0 -f "host 10.10.5.23 and (port 80 or port 443 or port 445)" -w /tmp/capture.pcapng

# Capture with ring buffer to manage disk usage (10 files, 100MB each)
tshark -i eth0 -b filesize:102400 -b files:10 -w /tmp/rolling_capture.pcapng

# Capture on multiple interfaces simultaneously
tshark -i eth0 -i eth1 -w /tmp/multi_interface.pcapng
```使用 Wireshark GUI 时，在开始捕获前于「捕获选项」中设置捕获过滤器。

### 第 2 步：应用显示过滤器做定向分析

```bash
# Filter HTTP traffic containing suspicious user agents
tshark -r capture.pcapng -Y "http.user_agent contains \"curl\" or http.user_agent contains \"Wget\""

# Find DNS queries to suspicious TLDs
tshark -r capture.pcapng -Y "dns.qry.name contains \".xyz\" or dns.qry.name contains \".top\" or dns.qry.name contains \".tk\""

# Identify TCP retransmissions indicating network issues
tshark -r capture.pcapng -Y "tcp.analysis.retransmission"

# Filter SMB traffic for lateral movement detection
tshark -r capture.pcapng -Y "smb2.cmd == 5 or smb2.cmd == 3" -T fields -e ip.src -e ip.dst -e smb2.filename

# Find cleartext credential transmission
tshark -r capture.pcapng -Y "ftp.request.command == \"PASS\" or http.authbasic"

# Detect beaconing patterns (regular interval connections)
tshark -r capture.pcapng -Y "ip.dst == 203.0.113.50" -T fields -e frame.time_relative -e ip.src -e tcp.dstport
```### 第 3 步：按协议深入分析```bash
# Follow a TCP stream to reconstruct a conversation
tshark -r capture.pcapng -q -z follow,tcp,ascii,0

# Analyze HTTP request/response pairs
tshark -r capture.pcapng -Y "http" -T fields -e frame.time -e ip.src -e ip.dst -e http.request.method -e http.request.uri -e http.response.code

# Extract DNS query/response statistics
tshark -r capture.pcapng -q -z dns,tree

# Analyze TLS handshakes for weak cipher suites
tshark -r capture.pcapng -Y "tls.handshake.type == 2" -T fields -e ip.src -e ip.dst -e tls.handshake.ciphersuite

# SMB file access enumeration
tshark -r capture.pcapng -Y "smb2" -T fields -e frame.time -e ip.src -e ip.dst -e smb2.filename -e smb2.cmd
```### 第 4 步：提取工件与 IOC```bash
# Export HTTP objects (files transferred over HTTP)
tshark -r capture.pcapng --export-objects http,/tmp/http_objects/

# Export SMB objects (files transferred over SMB)
tshark -r capture.pcapng --export-objects smb,/tmp/smb_objects/

# Extract all unique destination IPs for threat intelligence lookup
tshark -r capture.pcapng -T fields -e ip.dst | sort -u > unique_dest_ips.txt

# Extract SSL/TLS certificate information
tshark -r capture.pcapng -Y "tls.handshake.type == 11" -T fields -e x509sat.uTF8String -e x509ce.dNSName

# Extract all URLs accessed
tshark -r capture.pcapng -Y "http.request" -T fields -e http.host -e http.request.uri | sort -u > urls.txt

# Hash extracted files for IOC matching
find /tmp/http_objects/ -type f -exec sha256sum {} \; > extracted_file_hashes.txt
```### 第 5 步：统计分析与异常检测```bash
# Protocol hierarchy statistics
tshark -r capture.pcapng -q -z io,phs

# Conversation statistics sorted by bytes
tshark -r capture.pcapng -q -z conv,tcp -z conv,udp

# Identify top talkers
tshark -r capture.pcapng -q -z endpoints,ip

# IO graph data (packets per second)
tshark -r capture.pcapng -q -z io,stat,1,"COUNT(frame) frame"

# Detect port scanning patterns
tshark -r capture.pcapng -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" -T fields -e ip.src -e tcp.dstport | sort | uniq -c | sort -rn | head -20
```### 第 6 步：生成报告与导出证据```bash
# Export filtered packets to a new PCAP for evidence preservation
tshark -r capture.pcapng -Y "ip.addr == 10.10.5.23 and tcp.port == 4444" -w evidence_c2_traffic.pcapng

# Generate packet summary in CSV format
tshark -r capture.pcapng -T fields -E header=y -E separator=, -e frame.number -e frame.time -e ip.src -e ip.dst -e ip.proto -e tcp.srcport -e tcp.dstport -e frame.len > traffic_summary.csv

# Create PDML (XML) output for programmatic analysis
tshark -r capture.pcapng -T pdml > capture_analysis.xml

# Calculate capture file hash for chain of custody
sha256sum capture.pcapng > capture_hash.txt
```## 关键概念

| 术语 | 定义 |
|------|------|
| **捕获过滤器（BPF）** | 在捕获时应用的 Berkeley Packet Filter 语法，用于限制记录的包，减小文件并提升性能 |
| **显示过滤器** | Wireshark 专用语法，作用于已捕获数据，聚焦分析且不修改抓包文件 |
| **PCAPNG** | 下一代抓包格式，单文件可含多接口、名称解析、注释与元数据 |
| **TCP 流** | 重组后的 TCP 段序列，表示两端点间完整双向会话 |
| **协议解析器（Dissector）** | 解码特定协议字段与结构的 Wireshark 模块 |
| **IO 图** | 捕获时段内包速率或字节速率的时间序列可视化，用于发现流量尖峰或信标 |

## 工具与系统

- **Wireshark 4.0+**：带 3000+ 协议解析器的 GUI 分析器，支持流重组与导出
- **tshark**：Wireshark 的命令行版本，适合无界面抓包、批处理与脚本流水线
- **tcpdump**：轻量抓包工具，适合远程系统快速采集、无 GUI 依赖
- **mergecap**：合并多个抓包为单一 PCAP 以便统一分析
- **editcap**：切分、过滤与转换抓包格式

## 常见场景

### 场景：调查疑似经 DNS 隧道的外泄

**背景**：SOC 发现工作站 10.10.3.45 对外部域名 DNS 查询量异常；SIEM 显示约每分钟 200 次查询，基线为 15 次。已在工作站所在 VLAN 的分流器上启动抓包。

**做法**：

1. `tshark -i eth2 -f "host 10.10.3.45 and port 53" -w dns_exfil_investigation.pcapng`
2. 分析查询模式：`tshark -r dns_exfil_investigation.pcapng -Y "dns.qry.name contains \"suspect-domain.xyz\"" -T fields -e frame.time -e dns.qry.name`
3. 检查子域标签是否含编码数据（冗长类 base64 子域常提示隧道）：`tshark -r dns_exfil_investigation.pcapng -Y "dns.qry.type == 16" -T fields -e dns.qry.name -e dns.txt`
4. 汇总查询名长度估算外泄带宽
5. 提取唯一查询名并尝试解码 base64 子域以恢复外泄内容
6. 将证据包导出为独立 PCAP，并计算 SHA-256 以保全证据链

**易错点**：

- 在繁忙链路上无过滤抓包导致磁盘占满、未抓到关键数据
- 应用显示过滤器代替捕获过滤器，文件过大、处理缓慢
- 忽视 DoH/DoT 等加密 DNS，绕过传统 53 端口采集
- 未记录抓包哈希与取证保管链文档

## 输出格式

```
## 流量分析报告

**案例编号**: IR-2024-0847
**抓包文件**: dns_exfil_investigation.pcapng
**SHA-256**: a3f2b8c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1
**时段**: 2024-03-15 14:00:00 至 14:45:00 UTC
**源接口**: eth2（VLAN 30 SPAN 口）

### 发现

**1. 已确认 DNS 隧道**
- 源: 10.10.3.45
- 目的 DNS: 8.8.8.8（转发至 ns1.suspect-domain.xyz）
- 查询量: 45 分钟内 9,247 次（约 205/分钟，对比基线 15/分钟）
- 子域标签平均长度: 63 字符（base64 编码数据）
- 估算经 TXT 响应外泄: 约 2.3 MB

**2. 失陷指标（IOC）**
- 域名: suspect-domain.xyz（注册约 3 天）
- NS: ns1.suspect-domain.xyz (203.0.113.50)
- 查询模式: 含 base64 子域的 TXT 请求
- 响应模式: 含 base64 载荷的 TXT 记录
```