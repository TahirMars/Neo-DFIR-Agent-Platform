---
id: analyzing-malicious-url-with-urlscan
name: analyzing-malicious-url-with-urlscan
description: 通过 URLScan.io 界面与 API 安全分析可疑 URL（截图、网络、DOM）。
domain: cybersecurity
subdomain: phishing-defense
tags:
- phishing
- email-security
- social-engineering
- dmarc
- awareness
- url-analysis
- threat-intelligence
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 使用 URLScan 分析恶意 URL

## 概述
URLScan.io is a free service for scanning and analyzing suspicious URLs. It captures screenshots, DOM content, HTTP transactions, JavaScript behavior, and network connections of web pages in an isolated environment. 本技能涵盖 using URLScan's web interface and API to investigate phishing URLs, credential harvesting pages, and malicious redirects without exposing the analyst's system to risk.


## 使用时机

- 在需要运用本技能进行分析的安全事件调查中
- 需要为本领域构建检测规则或威胁狩猎查询时
- SOC 分析师需要此类分析的结构化流程时
- 需要验证与相关攻击技术有关的安全监控覆盖时

## 前置条件
- URLScan.io account (free tier available, API key for automation)
- Python 3.8+ with requests library
- Understanding of HTTP protocols and web technologies
- Familiarity with phishing URL patterns

## 关键概念

### URLScan Capabilities
1. **Safe browsing**: Renders URLs in isolated Chromium instance
2. **Screenshot capture**: Visual snapshot of the rendered page
3. **DOM analysis**: Full HTML content after JavaScript execution
4. **Network log**: All HTTP requests made by the page (HAR format)
5. **Certificate analysis**: SSL/TLS certificate details
6. **Technology detection**: Identifies web frameworks and libraries
7. **IP/ASN mapping**: Infrastructure intelligence
8. **Verdict**: Community and automated classification

### Phishing URL Red Flags
- Newly registered domains (< 30 days)
- Free hosting services (Wix, GitHub Pages, Firebase)
- URL shorteners hiding final destination
- Excessive subdomain depth (login.microsoft.com.evil.com)
- Brand name in subdomain or path, not domain
- Non-standard ports
- Data URIs or base64-encoded content
- JavaScript-heavy pages with minimal HTML

## 工作流程

### 第 1 步：Submit URL to URLScan
```
Web: Navigate to https://urlscan.io and submit the suspicious URL
API: POST https://urlscan.io/api/v1/scan/
     Header: API-Key: your-api-key
     Body: {"url": "https://suspicious-url.com", "visibility": "private"}
```

### 第 2 步：Analyze Results
- Review screenshot for brand impersonation
- Check redirects and final destination URL
- Examine DOM for credential input forms
- Review network requests for data exfiltration endpoints
- Check SSL certificate validity and issuer

### 第 3 步：Extract IOCs
- Domains and IPs contacted
- URLs in redirect chain
- SHA-256 hashes of page resources
- JavaScript file hashes

### 第 4 步：Cross-Reference with Threat Intelligence
Use the `scripts/process.py` to automate URL scanning, extract IOCs, and cross-reference with VirusTotal, PhishTank, and Google Safe Browsing.

## 工具与资源
- **URLScan.io**: https://urlscan.io/
- **URLScan API**: https://urlscan.io/docs/api/
- **VirusTotal URL Scanner**: https://www.virustotal.com/
- **PhishTank**: https://phishtank.org/
- **Google Safe Browsing**: https://transparencyreport.google.com/safe-browsing/search
- **Any.Run**: https://any.run/ (interactive sandbox)
- **Hybrid Analysis**: https://www.hybrid-analysis.com/

## 验证
- Successfully scan a suspicious URL via API
- Extract screenshot and identify brand impersonation
- Document complete redirect chain
- Generate IOC list from scan results
- Cross-reference findings with at least 2 threat intelligence sources