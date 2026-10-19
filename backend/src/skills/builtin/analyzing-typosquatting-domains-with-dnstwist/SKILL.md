---
id: analyzing-typosquatting-domains-with-dnstwist
name: analyzing-typosquatting-domains-with-dnstwist
name_zh: 分析·域名仿冒·域名·dnstwist
description: 使用 dnstwist 生成域名排列以检测误植域名、同形异义网络钓鱼和品牌假冒域名，识别针对组织的已注册相似域名。
domain: cybersecurity
subdomain: threat-intelligence
tags:
- dnstwist
- typosquatting
- phishing
- domain-monitoring
- brand-protection
- homograph
- dns
- threat-intelligence
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 分析·域名仿冒·域名·dnstwist

## 概述
DNSTwist 是一个域名排列引擎，通过生成外观相似的域名来检测域名抢注、同形异义词网络钓鱼攻击和品牌假冒。该工具采用字符替换、转置、插入、省略和同形文字替换等技术生成数千个域名排列，随后检查 DNS 记录（A、AAAA、NS、MX），使用模糊哈希 (ssdeep) 和感知哈希 (pHash) 计算网页相似度，并标记潜在的恶意注册域名。


## 使用时机
- 调查需要 dnstwist 分析误植域的安全事件时
- 构建该域的检测规则或威胁搜寻查询时
- 当 SOC 分析师需要结构化分析流程时
- 验证安全监控对相关攻击技术的覆盖范围时

## 前置条件
- 安装了 `dnstwist` 的 Python 3.9+ (`pip install dnstwist[full]`)
- 可选：用于 IP 地理定位的 GeoIP 数据库
- 可选：用于丰富结果的 Shodan API 密钥
- 网络访问权限以执行 DNS 查询
- 了解 DNS 记录类型和域名注册机制

## 关键概念

### 域排列技术

DNSTwist 通过以下方式生成排列：添加（附加字符）、位抢注（位翻转错误）、同形文字（视觉上相似的 Unicode 字符，如 rn 与 m）、连字符（添加连字符）、插入（插入字符）、省略（删除字符）、重复（重复字符）、替换（用相邻键盘键替换）、子域（插入点）、转置（交换相邻字符）、元音交换（交换元音）和基于字典（附加常用单词）。

### 模糊哈希和视觉相似度

DNSTwist 使用 ssdeep（位置敏感哈希）比较 HTML 内容，使用 pHash（感知哈希）比较网页截图。这有助于识别视觉上模仿合法网站的克隆钓鱼站点。高相似度分数表明可能是钓鱼页面。

### 检测工作流程

典型流程为：生成域名排列 -> 解析 DNS 记录 -> 检查注册域名 -> 比较网页相似性 -> 标记可疑域名 -> 向安全团队发出警报 -> 请求删除。对于企业域，dnstwist 通常生成 5,000-10,000 种排列。

## 工作流程
### 第1步：基本域排列扫描

```python
import subprocess
import json
import csv
from datetime import datetime

def run_dnstwist_scan(domain, output_file=None):
    """Run dnstwist scan against a target domain."""
    cmd = [
        "dnstwist",
        "--registered",     # Only show registered domains
        "--format", "json", # Output in JSON
        "--nameservers", "8.8.8.8,1.1.1.1",
        "--threads", "50",
        "--mxcheck",        # Check MX records
        "--ssdeep",         # Fuzzy hash comparison
        "--geoip",          # GeoIP lookup
        domain,
    ]

    print(f"[*] Scanning permutations for: {domain}")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

    if result.returncode == 0:
        results = json.loads(result.stdout)
        registered = [r for r in results if r.get("dns_a") or r.get("dns_aaaa")]
        print(f"[+] Found {len(registered)} registered lookalike domains")

        if output_file:
            with open(output_file, "w") as f:
                json.dump(registered, f, indent=2)
            print(f"[+] Results saved to {output_file}")

        return registered
    else:
        print(f"[-] dnstwist error: {result.stderr}")
        return []

results = run_dnstwist_scan("example.com", "typosquat_results.json")
```### 第 2 步：分析和优先级排序结果```python
def analyze_results(results, legitimate_ips=None):
    """Analyze dnstwist results and prioritize threats."""
    legitimate_ips = legitimate_ips or set()
    high_risk = []
    medium_risk = []
    low_risk = []

    for entry in results:
        domain = entry.get("domain", "")
        fuzzer = entry.get("fuzzer", "")
        dns_a = entry.get("dns_a", [])
        dns_mx = entry.get("dns_mx", [])
        ssdeep_score = entry.get("ssdeep_score", 0)

        risk_score = 0
        risk_factors = []

        # 高度相似于合法站点
        if ssdeep_score and ssdeep_score > 50:
            risk_score += 40
            risk_factors.append(f"high web similarity ({ssdeep_score}%)")

        # 包含 MX 记录（可接收邮件/钓鱼）
        if dns_mx:
            risk_score += 20
            risk_factors.append("has MX records (email capable)")

        # 最近注册（若 whois 数据可用）
        whois_created = entry.get("whois_created", "")
        if whois_created:
            try:
                created = datetime.fromisoformat(whois_created.replace("Z", "+00:00"))
                age_days = (datetime.now(created.tzinfo) - created).days
                if age_days < 30:
                    risk_score += 30
                    risk_factors.append(f"recently registered ({age_days} days)")
                elif age_days < 90:
                    risk_score += 15
                    risk_factors.append(f"registered {age_days} days ago")
            except (ValueError, TypeError):
                pass

        # 同形文字攻击风险最高
        if fuzzer == "homoglyph":
            risk_score += 25
            risk_factors.append("homoglyph (visually identical)")
        elif fuzzer in ("addition", "replacement", "transposition"):
            risk_score += 10
            risk_factors.append(f"permutation type: {fuzzer}")

        # 不指向合法基础设施
        if dns_a and not set(dns_a).intersection(legitimate_ips):
            risk_score += 10
            risk_factors.append("different IP from legitimate")

        entry["risk_score"] = risk_score
        entry["risk_factors"] = risk_factors

        if risk_score >= 50:
            high_risk.append(entry)
        elif risk_score >= 25:
            medium_risk.append(entry)
        else:
            low_risk.append(entry)

    high_risk.sort(key=lambda x: x["risk_score"], reverse=True)
    medium_risk.sort(key=lambda x: x["risk_score"], reverse=True)

    print(f"\n=== 误植域名分析 ===")
    print(f"高风险: {len(high_risk)}")
    print(f"中风险: {len(medium_risk)}")
    print(f"低风险: {len(low_risk)}")

    if high_risk:
        print(f"\n--- 高风险域名 ---")
        for entry in high_risk[:10]:
            print(f"  {entry['domain']} (分数: {entry['risk_score']})")
            for factor in entry['risk_factors']:
                print(f"    - {factor}")

    return {"high": high_risk, "medium": medium_risk, "low": low_risk}

analysis = analyze_results(results, legitimate_ips={"93.184.216.34"})
```### 第 3 步：持续监控流水线```python
import time
import hashlib

class TyposquatMonitor:
    def __init__(self, domains, known_domains_file="known_typosquats.json"):
        self.domains = domains
        self.known_file = known_domains_file
        self.known_domains = self._load_known()

    def _load_known(self):
        try:
            with open(self.known_file, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def _save_known(self):
        with open(self.known_file, "w") as f:
            json.dump(self.known_domains, f, indent=2)

    def scan_all_domains(self):
        """Scan all monitored domains for new typosquats."""
        new_findings = []
        for domain in self.domains:
            results = run_dnstwist_scan(domain)
            for entry in results:
                domain_key = entry.get("domain", "")
                if domain_key not in self.known_domains:
                    entry["first_seen"] = datetime.now().isoformat()
                    entry["monitored_domain"] = domain
                    self.known_domains[domain_key] = entry
                    new_findings.append(entry)
                    print(f"  [NEW] {domain_key} ({entry.get('fuzzer', '')})")

        self._save_known()
        print(f"\n[+] 新发现的误植域名: {len(new_findings)}")
        return new_findings

    def generate_alert(self, findings):
        """Generate alert for new high-risk typosquatting domains."""
        analysis = analyze_results(findings)
        alerts = []
        for entry in analysis["high"]:
            alerts.append({
                "severity": "HIGH",
                "domain": entry["domain"],
                "target": entry.get("monitored_domain", ""),
                "risk_score": entry["risk_score"],
                "risk_factors": entry["risk_factors"],
                "dns_a": entry.get("dns_a", []),
                "dns_mx": entry.get("dns_mx", []),
                "timestamp": datetime.now().isoformat(),
            })
        return alerts

monitor = TyposquatMonitor(["mycompany.com", "mycompany.org"])
new_findings = monitor.scan_all_domains()
alerts = monitor.generate_alert(new_findings)
```### 第 4 步：导出阻止列表和删除请求```python
def export_blocklist(analysis, output_file="blocklist.txt"):
    """Export high-risk domains as blocklist for firewall/proxy."""
    domains = []
    for entry in analysis["high"] + analysis["medium"]:
        domain = entry.get("domain", "")
        if domain:
            domains.append(domain)

    with open(output_file, "w") as f:
        f.write(f"# 误植域名阻止列表 {datetime.now().isoformat()}\n")
        for d in sorted(set(domains)):
            f.write(f"{d}\n")

    print(f"[+] 阻止列表已保存: {len(domains)} 域名 -> {output_file}")
    return domains

def generate_takedown_report(high_risk_domains):
    """Generate takedown request report."""
    report = f"""# 域名删除请求
生成时间: {datetime.now().isoformat()}

## 摘要
{len(high_risk_domains)} 域名被识别为潜在的误植域名/钓鱼域名。

## 需要删除的域名
"""
    for entry in high_risk_domains:
        report += f"""
### {entry['domain']}
- **排列类型**: {entry.get('fuzzer', '未知')}
- **IP 地址**: {', '.join(entry.get('dns_a', ['N/A']))}
- **MX 记录**: {', '.join(entry.get('dns_mx', ['N/A']))}
- **风险分数**: {entry.get('risk_score', 0)}
- **风险因素**: {'; '.join(entry.get('risk_factors', []))}
- **网页相似度**: {entry.get('ssdeep_score', 'N/A')}%
"""
    with open("takedown_report.md", "w") as f:
        f.write(report)
    print("[+] 删除报告已生成: takedown_report.md")

export_blocklist(analysis)
generate_takedown_report(analysis["high"])
```## 验证标准

- DNSTwist 生成目标域的排列组合
- DNS 解析可识别已注册的相似域名
- 网页相似度评分可检测克隆钓鱼页面
- 风险评分按威胁级别对域名排序
- 持续监控可发现新注册的仿冒域名
- 正确生成阻止列表和删除报告

## 参考资料
- [dnstwist GitHub 存储库](https://github.com/elceef/dnstwist)
- [dnstwister在线服务](https://dnstwister.report/)
- [HawkEye：使用 DNSTwist 检测误植](https://hawk-eye.io/2022/11/how-to-detect-typosquatting-using-dnstwist/)
- [Darktrace：监控域名仿冒域名](https://www.darktrace.com/blog/vigilance-in-action-monitoring-typosquatting-domains)
- [安全风险顾问：域监控](https://sra.io/blog/domain-monitoring-fast-and-cheap/)
- [Conscia：如何检测域名抢注](https://conscia.com/blog/diving-deep-how-to-detect-typosquatting/)