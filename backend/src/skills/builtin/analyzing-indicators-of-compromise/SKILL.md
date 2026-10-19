---
id: analyzing-indicators-of-compromise
name: analyzing-indicators-of-compromise
name_zh: 分析·指标·失陷
description: 对 IP、域名、哈希、URL 等 IOC 做多源富化与置信度分级，支撑阻断与研判决策。
domain: cybersecurity
subdomain: threat-intelligence
tags:
- IOC
- VirusTotal
- AbuseIPDB
- MalwareBazaar
- MISP
- threat-intelligence
- STIX
- NIST-CSF
version: 1.0.0
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- report
- general_chat
---

# 分析·指标·失陷

## 使用时机

在以下场景使用本技能：
- A phishing email or alert generates IOCs (URLs, IP addresses, file hashes) requiring rapid triage
- Automated feeds deliver bulk IOCs that need confidence scoring before ingestion into blocking controls
- An incident investigation requires contextual enrichment of observed network artifacts

**请勿仅凭**本技能在关键阻断决策中单独使用 — always combine automated enrichment with analyst judgment, especially for shared infrastructure (CDNs, cloud providers).

## 前置条件

- VirusTotal API key (free or Enterprise) for multi-AV and sandbox lookup
- AbuseIPDB API key for IP reputation checks
- MISP instance or TIP for cross-referencing against known campaigns
- Python with `requests` and `vt-py` libraries, or SOAR platform with pre-built connectors

## 工作流程

### 第 1 步：Normalize and Classify IOC Types

Before enriching, classify each IOC:
- **IPv4/IPv6 address**: Check if RFC 1918 private (skip external enrichment), validate format
- **Domain/FQDN**: Defang for safe handling (`evil[.]com`), extract registered domain via tldextract
- **URL**: Extract domain + path separately; check for redirectors
- **File hash**: Identify hash type (MD5/SHA-1/SHA-256); prefer SHA-256 for uniqueness
- **Email address**: Split into domain (check MX/DMARC) and local part for pattern analysis

Defang IOCs in documentation (replace `.` with `[.]` and `://` with `[://]`) to prevent accidental clicks.

### 第 2 步：Multi-Source Enrichment

**VirusTotal (file hash, URL, IP, domain)**:```python
import vt

client = vt.Client("YOUR_VT_API_KEY")

# File hash lookup
file_obj = client.get_object(f"/files/{sha256_hash}")
detections = file_obj.last_analysis_stats
print(f"Malicious: {detections['malicious']}/{sum(detections.values())}")

# Domain analysis
domain_obj = client.get_object(f"/domains/{domain}")
print(domain_obj.last_analysis_stats)
print(domain_obj.reputation)
client.close()
```**滥用IPDB（IP地址）**：```python
import requests

response = requests.get(
    "https://api.abuseipdb.com/api/v2/check",
    headers={"Key": "YOUR_KEY", "Accept": "application/json"},
    params={"ipAddress": "1.2.3.4", "maxAgeInDays": 90}
)
data = response.json()["data"]
print(f"Confidence: {data['abuseConfidenceScore']}%, Reports: {data['totalReports']}")
```**MalwareBazaar（文件哈希）**：```python
response = requests.post(
    "https://mb-api.abuse.ch/api/v1/",
    data={"query": "get_info", "hash": sha256_hash}
)
result = response.json()
if result["query_status"] == "ok":
    print(result["data"][0]["tags"], result["data"][0]["signature"])
```### 第 3 步：结合营销活动归因进行情境化

查询 MISP 是否存在与 IOC 匹配的事件：```python
from pymisp import PyMISP

misp = PyMISP("https://misp.example.com", "API_KEY")
results = misp.search(value="evil-domain.com", type_attribute="domain")
for event in results:
    print(event["Event"]["info"], event["Event"]["threat_level_id"])
```检查 Shodan 的 IP 上下文（托管提供商、开放端口、横幅），以确定 IP 是否属于防弹托管或合法的云提供商（误报风险）。

###第4步：分配置信度分数和处置

应用分层决策框架：
- **阻止（高置信度 ≥ 70%）**：VT 上检测到 ≥15 个 AV，AbuseIPDB 得分 ≥70，与已知恶意软件系列或活动匹配
- **监控/警报（中 40–69%）**：5–14 次 AV 检测，中等 AbuseIPDB 评分，无活动归因
- **白名单/调查（低 <40%）**：≤4 次 AV 检测，无滥用报告，合法服务（Google、Cloudflare CDN IP）
- **误报**：合法的商业服务被错误标记；记录并从未来的警报中排除

### 第 5 步：记录并分发

在 TIP/MISP 中记录结果：
- 收集的所有丰富数据（时间戳、来源、分数）
- 处置决定及理由
- 采取的阻止操作（防火墙、代理、DNS 污水坑）
- 相关事件票号

导出到 STIX 指标对象并适当设置置信字段。

## 关键概念

| 术语 | 定义 |
|------|------------|
| **国际奥委会** |妥协指标——可观察到的网络或主机工件表明潜在的妥协|
| **丰富** |将来自多个情报源的上下文数据添加到原始 IOC 的过程 |
| **拔牙** |修改 IOC（将 `.` 替换为 `[.]`）以防止文档中的意外激活 |
| **误报率** |良性工件被错误标记为恶意的百分比；对于调整块阈值至关重要|
| **天坑** | DNS 服务器将恶意域查找重定向到良性 IP 进行检测，而不会完全阻止流量 |
| **TTL** |阻塞控制中 IOC 的生存时间； IP 指标应在 30 天后过期，域名应在 90 天后过期 |

## 工具与系统

- **VirusTotal**：多引擎恶意软件扫描程序和威胁情报平台，具有 70 多个 AV 引擎、沙箱报告和社区评论
- **AbuseIPDB**：社区维护的 IP 声誉数据库，具有 90 天的滥用报告历史记录
- **MalwareBazaar (abuse.ch)**：具有 YARA 规则关联和恶意软件系列标记的免费恶意软件哈希存储库
- **URLScan.io**：免费的 URL 分析服务，可捕获屏幕截图、DOM 和网络请求以进行网络钓鱼 URL 分类
- **Shodan**：互联网范围内的扫描数据，提供托管提供商、开放端口和用于 IP 丰富的横幅信息

## 常见陷阱

- **阻止共享基础设施**：CDN IP（Cloudflare 104.21.x.x、AWS CloudFront）可能合法托管恶意内容，但阻止 IP 会破坏数千个合法站点。
- **VT 分数痴迷**：低 VT 检测计数并不意味着良性 — 零日恶意软件和自定义 APT 工具最初通常得分为 0。检查沙箱行为、MISP 和被动 DNS。
- **缺少防攻击**：在电子邮件或 Confluence 文档中粘贴实时 IOC 可能会触发自动 URL 扫描程序或网络钓鱼工具。
- **无过期政策**：没有 TTL 的 IOC 会无限期地累积在阻止列表中，当基础设施被合法用户重新利用时，会产生误报。
- **过度依赖单一来源**：VirusTotal 汇总了 AV 意见 - 所有意见都可能是错误的或落后于新兴恶意软件。使用 3 个以上的独立来源进行高风险决策。