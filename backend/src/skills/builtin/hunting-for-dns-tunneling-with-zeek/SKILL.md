---
id: hunting-for-dns-tunneling-with-zeek
name: hunting-for-dns-tunneling-with-zeek
name_zh: 威胁狩猎·DNS·隧道·Zeek
description: 通过分析 Zeek dns.log 中的高熵子域查询、过量查询量、异常查询长度与非常规记录类型，检测 DNS 隧道与经 DNS 隐蔽信道的外泄（MITRE
  T1071.004 等）。
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- dns-tunneling
- zeek
- data-exfiltration
- covert-channel
- mitre-t1071-004
- network-monitoring
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 威胁狩猎·DNS·隧道·Zeek

## 使用时机

- 猎杀经 DNS 隐蔽信道的数据外泄
- 威胁情报表明所在行业正被基于 DNS 的 C2 框架针对
- dns.log 显示对特定域名的异常高查询量
- 怀疑数据窃取但未发现 HTTP/S 外泄时的调查
- 监控 iodine、dnscat2、DNSExfiltrator 或 DNS-over-HTTPS 隧道等工具

## 前置条件

- Zeek 部署于网络 TAP 或 SPAN，捕获 DNS 流量
- 含完整查询与响应字段的 Zeek dns.log
- 用于 dns.log 分析的 SIEM（Splunk、Elastic）
- RITA（Real Intelligence Threat Analytics）用于自动化 DNS 分析
- 被动 DNS 数据以提供历史解析上下文

## 工作流程

1. **分析查询长度分布**：DNS 隧道将数据编码在子域标签中，查询长度显着长于正常。正常 DNS 查询平均约 20–30 字符；隧道查询常超过 50 字符。按域计算查询长度的均值与标准差。
2. **计算子域熵**：隧道使用 Base32/Base64 编码产生高熵子域字符串。计算子域标签的香农熵——高于约 3.5 比特/字符强烈暗示编码数据。
3. **统计每域唯一子域数**：合法域名的唯一子域相对较少；DNS 隧道可在单一父域下生成数百或数千唯一子域。
4. **监控记录类型分布**：TXT、NULL、CNAME、MX 可比 A 记录承载更多数据。对单一域的过量 TXT 查询表明经 DNS 传输数据。
5. **检测高查询量**：标记单源每小时超过 100 次查询的域名，尤其当与子域高唯一性结合时。
6. **分析查询时序**：DNS 隧道工具可产生规律查询（信标）或突发（数据传输）。对 DNS 查询时间戳做频率分析。
7. **与 conn.log 交叉引用**：将可疑 DNS 查询与连接元数据关联，定位产生查询的进程或端点。
8. **域名情报验证**：将可疑域与 WHOIS、证书透明度与威胁情报比对。

## 关键概念

| 概念 | 说明 |
|---------|-------------|
| T1071.004 | 应用层协议：DNS |
| T1048.003 | 经替代协议外泄：DNS |
| T1572 | 协议隧道 |
| 香农熵 | 子域字符串随机性度量 |
| Zeek dns.log | DNS 查询/响应元数据 |
| RITA | 从 Zeek 日志自动化检测 DNS 隧道 |
| iodine | 经 DNS 的 IPv4 隧道工具 |
| dnscat2 | 基于 DNS 的 C2 工具 |
| DNSExfiltrator | 利用 DNS 请求外泄数据的工具 |

## 检测查询

### Zeek 脚本——DNS 隧道检测

```zeek
@load base/protocols/dns
module DNSTunnel;

export {
    redef enum Notice::Type += { DNSTunnel::Long_DNS_Query };
    const query_length_threshold = 50 &redef;
    const query_count_threshold = 100 &redef;
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    if ( |query| > query_length_threshold ) {
        NOTICE([$note=DNSTunnel::Long_DNS_Query,
                $msg=fmt("Long DNS query detected: %s (%d chars)", query, |query|),
                $conn=c]);
    }
}
```### Splunk——来自 Zeek 的 DNS 隧道指标```spl
index=zeek sourcetype=bro_dns
| rex field=query "(?<subdomain>[^.]+)\.(?<basedomain>[^.]+\.[^.]+)$"
| stats count dc(subdomain) as unique_subs avg(len(query)) as avg_len max(len(query)) as max_len by src basedomain
| where count > 100 AND (unique_subs > 50 OR avg_len > 40)
| sort -unique_subs
```### Splunk——高熵子域检测```spl
index=zeek sourcetype=bro_dns
| rex field=query "^(?<subdomain>[^.]+)"
| where len(subdomain) > 20
| eval char_count=len(subdomain)
| stats count dc(query) as unique_queries avg(char_count) as avg_sub_len by src query_type_name basedomain
| where unique_queries > 30 AND avg_sub_len > 25
| sort -unique_queries
```### RITA 分析```bash
rita import /path/to/zeek/logs dataset_name
rita show-dns-fqdn-ips-long dataset_name
rita show-exploded-dns dataset_name
rita show-dns-tunneling dataset_name --csv > dns_tunnel_results.csv
```## 常见场景

1. **dnscat2 C2**：在 DNS CNAME/TXT 查询中使用 Base64 编码子域标签承载 C2，产生高查询量与长、高熵子域。
2. **iodine IPv4 隧道**：创建虚拟网卡经 DNS 隧道传输 IP 流量，产生大量 DNS 查询与 NULL 记录类型。
3. **经 DNS 外泄**：敏感数据编码在子域标签中（如 `aGVsbG8gd29ybGQ.exfil.attacker.com`），以 A 或 TXT 查询发送，每次查询约携带 63 字节。
4. **DNS-over-HTTPS 隧道**：经 HTTPS 向公共解析器发送 DNS，绕过传统 DNS 监控，需 TLS 检查才能检测。
5. **Cobalt Strike DNS 信标**：使用 DNS A/TXT 进行 C2，子域编码方案可配置。

## 输出格式

```
猎杀 ID: TH-DNSTUNNEL-[DATE]-[SEQ]
源 IP: [内网 IP]
源主机: [主机名]
目标域: [父域]
查询次数: [时间窗口内总查询]
唯一子域数: [数量]
平均查询长度: [字符]
最大查询长度: [字符]
子域熵: [每字符比特]
主要记录类型: [A/TXT/CNAME/NULL]
数据量估算: [外泄字节数]
风险级别: [严重/高/中/低]
```