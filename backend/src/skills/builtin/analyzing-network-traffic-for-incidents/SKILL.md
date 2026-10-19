---
id: analyzing-network-traffic-for-incidents
name: analyzing-network-traffic-for-incidents
name_zh: 分析·网络·流量·事件
description: 分析网络流量捕获和流数据以识别安全事件中的攻击者活动，包括命令与控制通信、横向移动、数据泄露和利用尝试。使用 Wireshark、Zeek
  和 NetFlow 分析技术。适用于需要网络流量分析、数据包捕获调查、PCAP 分析、网络取证、C2 通信检测或数据泄露检测的请求。
domain: cybersecurity
subdomain: incident-response
tags:
- network-forensics
- PCAP-analysis
- Wireshark
- Zeek
- traffic-analysis
version: 1.0.0
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 分析·网络·流量·事件

## 使用时机
- SIEM 报警显示需要深入调查的异常网络流量模式
- 怀疑存在 C2 信标活动，需通过数据包级分析确认
- 需要从网络证据中量化数据泄露量或目标地址
- 需要通过网络连接追踪系统间的横向移动
- IDS/IPS 报警需要数据包级验证以确认或排除

**请勿使用** 于基于主机的取证分析（进程执行、文件系统痕迹）；应使用端点取证工具。

## 前置条件
- 完整数据包捕获（PCAP）基础设施或按需捕获能力（网络分流器、SPAN 端口）
- 分析工作站已安装 Wireshark 并掌握适当显示过滤器知识
- 部署 Zeek（原 Bro）以生成网络元数据（conn.log、dns.log、http.log、ssl.log）
- 从网络设备收集 NetFlow/IPFIX 数据以进行流量分析
- 显示 VLAN 布局、防火墙位置和监控点的网络架构图
- 用于关联观察网络指标的威胁情报源

## 工作流程
### 第 1 步：捕获或获取网络流量

获取调查相关的流量数据：

**实时捕获（若事件正在进行）：**```bash
# 在特定接口上按主机过滤捕获
tcpdump -i eth0 -w capture.pcap host 10.1.5.42

# 捕获到特定外部 IP 的 C2 流量
tcpdump -i eth0 -w c2_traffic.pcap host 185.220.101.42

# 带轮转的捕获（1GB 文件，保留 10 个）
tcpdump -i eth0 -w capture_%Y%m%d%H%M.pcap -C 1000 -W 10
```**从现有基础设施获取：**
- 从完整数据包捕获设备导出 PCAP（Arkime/Moloch、ExtraHop、Corelight）
- 从 Zeek 集群获取调查时间范围内的 Zeek 日志
- 从网络设备导出 NetFlow 数据以进行高层流量分析

### 第 2 步：识别 C2 通信

检测命令与控制流量模式：

**信标活动检测（Zeek conn.log）：**```bash
# 提取到外部 IP 的定期连接
cat conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p duration orig_bytes resp_bytes \
  | awk '$4 ~ /^185\.220/' | sort -t. -k1,1n -k2,2n
```**Wireshark 信标分析：**```
# 过滤到可疑 C2 IP 的流量
ip.addr == 185.220.101.42

# 过滤非标准端口的 HTTPS 流量
tcp.port != 443 && ssl

# 过滤可疑域名的 DNS 查询
dns.qry.name contains "evil" or dns.qry.name matches "^[a-z0-9]{32}\."

# 过滤 HTTP POST（常见 C2 登录方法）
http.request.method == "POST" && ip.dst == 185.220.101.42
```需识别的信标特征：
- 连接时间间隔规律（例如每 60 秒一次，允许 10-15% 的抖动）
- 请求和响应中的数据包大小一致
- HTTPS 到与合法 CDN 或服务无关的外部 IP
- 子域名高熵的 DNS 查询（DNS 隧道指示器）

### 第 3 步：分析横向移动流量

追踪攻击者在内部系统间的移动：```
关键协议用于横向移动检测：
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SMB（TCP 445）：     PsExec、文件共享访问、勒索软件传播
RDP（TCP 3389）：    远程桌面会话
WinRM（TCP 5985）：  PowerShell 远程操作
WMI（TCP 135）：     远程命令执行
SSH（TCP 22）：      Linux 横向移动
DCE/RPC（TCP 135）： 基于 DCOM 的横向移动
```**Wireshark 横向移动过滤器：**```
# SMB 横向移动
smb2 && ip.src == 10.1.5.42 && ip.dst != 10.1.5.42

# 被入侵主机的 RDP 连接
tcp.dstport == 3389 && ip.src == 10.1.5.42

# Kerberos 票据请求（潜在票据传递）
kerberos.msg_type == 12 && ip.src == 10.1.5.42

# NTLM 身份验证（潜在哈希传递）
ntlmssp.auth.username && ip.src == 10.1.5.42
```### 第 4 步：检测数据泄露

识别未经授权的网络数据传输：```bash
# 在 Zeek conn.log 中识别大流量外发
cat conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p orig_bytes \
  | awk '$5 > 100000000' | sort -t$'\t' -k5 -rn

# DNS 隧道检测（大量 TXT 查询）
cat dns.log | zeek-cut query qtype | grep TXT | cut -f1 \
  | rev | cut -d. -f1,2 | rev | sort | uniq -c | sort -rn | head

# 非常规协议使用（ICMP 隧道、DNS over HTTPS）
cat conn.log | zeek-cut proto id.resp_p orig_bytes | awk '$1 == "icmp" && $3 > 1000'
```**Wireshark 泄露过滤器：**```
# 大型 HTTP POST 上传
http.request.method == "POST" && tcp.len > 10000

# FTP 数据传输
ftp-data && ip.src == 10.0.0.0/8

# 带大型 TXT 响应的 DNS（隧道）
dns.resp.type == 16 && dns.resp.len > 200
```### 第 5 步：提取并关联网络 IOCs

从流量分析中提取网络相关指标：

- 被入侵主机联系的外部 IP 地址
- 事件时间范围内通过 DNS 解析的域名
- 通过 HTTP/HTTPS 访问的 URL（若部署了 SSL 解密）
- TLS 证书细节（主题、颁发者、序列号、JA3/JA3S 哈希）
- HTTP 请求中的 User-Agent 字符串
- PCAP 中捕获的文件传输（使用 Wireshark 导出对象功能提取）

### 第 6 步：记录网络取证发现

将分析整理为结构化报告并引用证据：

- 为每个发现引用特定 PCAP 文件、帧号和时间戳
- 以截图或导出 PDF 形式包含关键证据的数据包捕获
- 将网络活动映射到事件时间线
- 将网络发现与端点取证的主机证据关联

## 关键概念

| 术语 | 定义 |
|------|------------|
| **PCAP（数据包捕获）** | 存储从网络接口捕获的原始网络数据包的文件格式，用于离线分析 |
| **信标活动** | 被入侵主机通过一致的时间间隔定期连接 C2 服务器的网络行为 |
| **JA3/JA3S** | 基于 ClientHello 和 ServerHello 参数的 TLS 客户端/服务器指纹方法，每个应用程序唯一 |
| **NetFlow/IPFIX** | 路由器和交换机收集的网络流量元数据（源、目标、端口、字节数、持续时间），无需完整数据包捕获 |
| **DNS 隧道** | 通过 DNS 查询和响应编码数据以实现数据泄露或维持 C2 通信的技术 |
| **网络分流器** | 创建网络流量精确副本的硬件设备，用于监控且不影响网络性能 |
| **Zeek 日志** | Zeek 网络分析框架生成的结构化元数据日志，涵盖连接、DNS、HTTP、SSL 等内容 |

## 工具与系统

- **Wireshark**：开源数据包分析器，用于在数据包级别深入检查网络协议
- **Zeek (原 Bro)**：网络分析框架，可从实时或捕获的流量中生成结构化元数据日志
- **Arkime (原 Moloch)**：开源的完整数据包捕获和搜索平台，适用于大规模网络取证
- **NetworkMiner**：网络取证分析工具，用于从 PCAP 文件中提取文件、图片和凭据
- **RITA (Real Intelligence Threat Analytics)**：用于 Zeek 日志的开源信标检测和 DNS 隧道分析工具

## 常见场景

### 场景：确认 C2 信标活动并量化泄露数据

**背景**：EDR 检测到工作站上的可疑进程，但无法确定数据泄露量。网络团队提供了覆盖事件时间范围的完整数据包捕获设备 PCAP。

**方法**：
1. 过滤 PCAP 中从被入侵主机 IP 到外部目标的流量
2. 通过分析连接时间模式（信标检测）识别 C2 通道
3. 从 C2 连接中提取 TLS 证书和 JA3 哈希以生成 IOC
4. 计算事件期间发送到 C2 基础设施的总字节数
5. 检查其他泄露通道（DNS 隧道、云存储上传）
6. 使用 Wireshark 导出对象功能提取通过未加密通道传输的任何文件

**陷阱**：
- 仅分析 HTTP 流量，而 C2 使用 HTTPS 且未部署 SSL 解密
- 每个 DNS 查询的数据量较小（但总时间累积显着）时遗漏 DNS 隧道
- 未关联网络时间戳与端点时间戳（时区不匹配）
- 忽视被滥用于泄露的合法云服务（OneDrive、Google Drive、Dropbox）

## 输出格式

```
网络流量分析报告
=================================
事件编号：         INC-2025-1547
分析师：           [姓名]
捕获源：           Arkime 完整数据包捕获
分析时段：         2025-11-15 14:00 UTC - 2025-11-15 18:00 UTC
总 PCAP 大小：     4.7 GB

C2 通信
源：               10.1.5.42 (WKSTN-042)
目标：             185.220.101.42:443 (HTTPS)
信标间隔：         60 秒 ± 12% 抖动
会话数：           4 小时内 237 次连接
JA3 哈希：         a0e9f5d64349fb13191bc781f81f42e1
TLS 证书：         CN=update.evil[.]com（自签名）
总发送数据：       147 MB（外发）
总接收数据：       2.3 MB（入站 - 命令）

横向移动
10.1.5.42 → 10.1.10.15 (SMB, TCP 445) - 14:35 UTC
10.1.5.42 → 10.1.10.20 (RDP, TCP 3389) - 14:42 UTC
10.1.5.42 → 10.1.1.5  (LDAP, TCP 389) - 15:10 UTC

泄露总结
协议：             HTTPS 到 C2 服务器
流量：             147 MB 外发
时段：             14:23 UTC - 18:00 UTC
提取文件：         [列出可通过未加密通道恢复的文件]

DNS 分析
可疑查询：         0 DNS 隧道指示器
DGA 检测：         0 算法生成域名

证据引用
PCAP 文件：        INC-2025-1547_capture.pcap (SHA-256: ...)
Zeek 日志：        /logs/zeek/2025-11-15/ (conn.log, ssl.log, dns.log)
```