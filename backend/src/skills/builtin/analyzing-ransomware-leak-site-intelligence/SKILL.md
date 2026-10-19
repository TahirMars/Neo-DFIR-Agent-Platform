---
id: analyzing-ransomware-leak-site-intelligence
name: analyzing-ransomware-leak-site-intelligence
name_zh: 分析·勒索软件·泄露·站点·情报
description: 监控勒索软件团体在 Tor 隐藏服务上维护的数据泄露站点 (DLS)，以获取受害者信息、威胁情报和行业风险评估。该技能包含从公开源提取数据、分析活动趋势、生成情报报告等步骤，要求使用
  Python 脚本和 Tor 代理进行安全分析。
domain: cybersecurity
subdomain: threat-intelligence
tags:
- ransomware
- leak-site
- data-leak
- extortion
- threat-intelligence
- monitoring
- dls
- victim-tracking
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 分析·勒索软件·泄露·站点·情报

## 概述
采用双重勒索模式的勒索软件团体通过 Tor 隐藏服务维护数据泄露站点 (DLS)，在其中发布受害者名称、被盗数据样本和倒计时器以迫使支付赎金。2025 年上半年，有 96 个独特的勒索软件团体活跃，每月列出约 535 名受害者。监控这些站点可提供有关活跃威胁团体、目标部门、地理模式和新兴勒索软件系列的情报。该技能涵盖安全收集 DLS 情报、提取结构化数据、跟踪群体活动趋势以及生成特定部门的风险评估。


## 使用时机
- 调查需要分析勒索软件泄漏站点情报的安全事件时
- 为该域构建检测规则或威胁搜寻查询时
- 当 SOC 分析师需要这种分析类型的结构化程序时
- 验证相关攻击技术的安全监控覆盖范围时

## 前置条件
- Python 3.9+，带有“requests”、“beautifulsoup4”、“pandas”、“matplotlib”库
- 用于访问 .onion 站点或商业 DLS 监控源的 Tor 代理 (SOCKS5)
- 了解勒索软件双重勒索商业模式
- 熟悉主要勒索软件家族（Qilin、Akira、LockBit、BlackCat、Clop）
- 访问勒索软件跟踪源（Ransomwatch、RansomLook、DarkFeed）

## 关键概念

### 双重勒索模型

现代勒索软件团体会对受害者数据进行加密，并在加密之前将其泄露。泄露网站起到了公众压力的作用：列出了受害者名单，并附有倒计时器、部分数据样本和文件树。如果不支付赎金，完整数据将被公布。一些组织已转向三重勒索，增加 DDoS 威胁或直接联系受害者的客户。

### DLS 情报价值

泄露网站提供：受害者识别（公司名称、部门、国家）、攻击时间表（列出时间、截止日期、发布数据）、数据量估计、团体能力评估（目标部门、攻击频率、行动节奏）和趋势分析（新团体出现、团体品牌重塑、执法取缔）。

### 安全收集实践

切勿直接访问生产环境中的 DLS 站点。使用专门构建的监控服务（Ransomwatch、DarkFeed、KELA、Flashpoint）、Tor 隔离的研究虚拟机、商业威胁情报平台或社区维护的数据集。所有分析都应在具有适当授权的隔离环境中进行。

## 工作流程
### 第 1 步：从公共源中提取勒索软件泄漏站点数据

```python
import requests
import json
import pandas as pd
from datetime import datetime, timedelta
from collections import Counter

class RansomwareIntelCollector:
    """Collect ransomware DLS intelligence from public tracking sources."""

    RANSOMWATCH_API = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"
    RANSOMWATCH_GROUPS = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/groups.json"

    def __init__(self):
        self.posts = []
        self.groups = []

    def fetch_ransomwatch_data(self):
        """Fetch ransomware victim posts from ransomwatch."""
        resp = requests.get(self.RANSOMWATCH_API, timeout=30)
        if resp.status_code == 200:
            self.posts = resp.json()
            print(f"[+] Loaded {len(self.posts)} victim posts from ransomwatch")
        else:
            print(f"[-] Failed to fetch posts: {resp.status_code}")

        resp = requests.get(self.RANSOMWATCH_GROUPS, timeout=30)
        if resp.status_code == 200:
            self.groups = resp.json()
            print(f"[+] Loaded {len(self.groups)} ransomware group profiles")

        return self.posts

    def get_recent_victims(self, days=30):
        """Get victims posted in the last N days."""
        cutoff = datetime.now() - timedelta(days=days)
        recent = []
        for post in self.posts:
            try:
                discovered = datetime.fromisoformat(
                    post.get("discovered", "").replace("Z", "+00:00")
                )
                if discovered.replace(tzinfo=None) >= cutoff:
                    recent.append(post)
            except (ValueError, TypeError):
                continue
        print(f"[+] {len(recent)} victims in last {days} days")
        return recent

    def get_group_activity(self, group_name):
        """Get all posts by a specific ransomware group."""
        group_posts = [
            p for p in self.posts
            if p.get("group_name", "").lower() == group_name.lower()
        ]
        print(f"[+] {group_name}: {len(group_posts)} total victims")
        return group_posts

collector = RansomwareIntelCollector()
collector.fetch_ransomwatch_data()
recent = collector.get_recent_victims(days=30)
```### 第2步：分析群体活动和趋势```python
def analyze_group_trends(posts, top_n=15):
    """Analyze ransomware group activity trends."""
    group_counts = Counter(p.get("group_name", "unknown") for p in posts)
    monthly_activity = {}

    for post in posts:
        try:
            date = datetime.fromisoformat(
                post.get("discovered", "").replace("Z", "+00:00")
            )
            month_key = date.strftime("%Y-%m")
            group = post.get("group_name", "unknown")
            if month_key not in monthly_activity:
                monthly_activity[month_key] = Counter()
            monthly_activity[month_key][group] += 1
        except (ValueError, TypeError):
            continue

    analysis = {
        "total_posts": len(posts),
        "unique_groups": len(group_counts),
        "top_groups": group_counts.most_common(top_n),
        "monthly_totals": {
            month: sum(counts.values())
            for month, counts in sorted(monthly_activity.items())
        },
        "monthly_top_groups": {
            month: counts.most_common(5)
            for month, counts in sorted(monthly_activity.items())
        },
    }

    print(f"\n=== Ransomware Group Activity ===")
    print(f"Total victims tracked: {analysis['total_posts']}")
    print(f"Active groups: {analysis['unique_groups']}")
    print(f"\nTop {top_n} Groups:")
    for group, count in analysis["top_groups"]:
        print(f"  {group}: {count} victims")

    return analysis

trends = analyze_group_trends(collector.posts)
```### 第 3 步：Sector and Geographic Risk Assessment```python
def assess_sector_risk(posts, target_sector=None, target_country=None):
    """Assess ransomware risk for specific sector or geography."""
    sector_data = {}
    country_data = {}

    for post in posts:
        # Extract sector if available (not all feeds include this)
        sector = post.get("sector", post.get("industry", "unknown"))
        country = post.get("country", "unknown")

        if sector not in sector_data:
            sector_data[sector] = {"count": 0, "groups": Counter(), "recent": []}
        sector_data[sector]["count"] += 1
        sector_data[sector]["groups"][post.get("group_name", "")] += 1

        if country not in country_data:
            country_data[country] = {"count": 0, "groups": Counter()}
        country_data[country]["count"] += 1
        country_data[country]["groups"][post.get("group_name", "")] += 1

    # Sector risk scoring
    total = len(posts)
    risk_assessment = {
        "total_victims": total,
        "sectors": {},
        "countries": {},
    }

    for sector, data in sorted(sector_data.items(), key=lambda x: -x[1]["count"]):
        pct = (data["count"] / total * 100) if total > 0 else 0
        risk_assessment["sectors"][sector] = {
            "victim_count": data["count"],
            "percentage": round(pct, 1),
            "top_groups": data["groups"].most_common(5),
            "risk_level": (
                "critical" if pct > 15
                else "high" if pct > 8
                else "medium" if pct > 3
                else "low"
            ),
        }

    for country, data in sorted(country_data.items(), key=lambda x: -x[1]["count"]):
        pct = (data["count"] / total * 100) if total > 0 else 0
        risk_assessment["countries"][country] = {
            "victim_count": data["count"],
            "percentage": round(pct, 1),
            "top_groups": data["groups"].most_common(5),
        }

    return risk_assessment

risk = assess_sector_risk(collector.posts)
```### 第 4 步：追踪新兴和品牌重塑团体```python
def track_new_groups(posts, lookback_days=90):
    """Identify newly emerged ransomware groups."""
    group_first_seen = {}
    for post in posts:
        group = post.get("group_name", "")
        try:
            date = datetime.fromisoformat(
                post.get("discovered", "").replace("Z", "+00:00")
            )
            if group not in group_first_seen or date < group_first_seen[group]["first_seen"]:
                group_first_seen[group] = {
                    "first_seen": date,
                    "first_victim": post.get("post_title", ""),
                }
        except (ValueError, TypeError):
            continue

    cutoff = datetime.now() - timedelta(days=lookback_days)
    new_groups = {
        group: info for group, info in group_first_seen.items()
        if info["first_seen"].replace(tzinfo=None) >= cutoff
    }

    # Count total victims per new group
    for group in new_groups:
        victims = [p for p in posts if p.get("group_name") == group]
        new_groups[group]["total_victims"] = len(victims)
        new_groups[group]["avg_per_month"] = round(
            len(victims) / max(1, lookback_days / 30), 1
        )

    print(f"\n=== New Groups (last {lookback_days} days) ===")
    for group, info in sorted(new_groups.items(), key=lambda x: -x[1]["total_victims"])[:10]:
        print(f"  {group}: {info['total_victims']} victims, "
              f"first seen {info['first_seen'].strftime('%Y-%m-%d')}")

    return new_groups

new_groups = track_new_groups(collector.posts, lookback_days=90)
```### 第 5 步：Generate Intelligence Report```python
def generate_ransomware_intel_report(trends, risk, new_groups):
    """Generate ransomware threat intelligence report."""
    report = f"""# Ransomware Threat Intelligence Report
Generated: {datetime.now().isoformat()}

## Executive Summary
- **Total victims tracked**: {trends['total_posts']}
- **Active ransomware groups**: {trends['unique_groups']}
- **New groups (last 90 days)**: {len(new_groups)}

## Top Active Groups
| Rank | Group | Victims |
|------|-------|---------|
"""
    for i, (group, count) in enumerate(trends["top_groups"][:10], 1):
        report += f"| {i} | {group} | {count} |\n"

    report += "\n## New Emerging Groups\n"
    for group, info in sorted(new_groups.items(), key=lambda x: -x[1]["total_victims"])[:10]:
        report += f"- **{group}**: {info['total_victims']} victims since {info['first_seen'].strftime('%Y-%m-%d')}\n"

    report += "\n## Sector Risk Assessment\n"
    report += "| Sector | Victims | % | Risk Level |\n|--------|---------|---|------------|\n"
    for sector, data in list(risk["sectors"].items())[:10]:
        report += f"| {sector} | {data['victim_count']} | {data['percentage']}% | {data['risk_level'].upper()} |\n"

    report += """
## Recommendations
1. Monitor DLS feeds daily for your organization and supply chain partners
2. Prioritize patching vulnerabilities exploited by top active groups
3. Implement offline backup strategy to reduce extortion leverage
4. Conduct tabletop exercises for ransomware scenario response
5. Share indicators with sector ISACs and threat sharing communities
"""
    with open("ransomware_intel_report.md", "w") as f:
        f.write(report)
    print("[+] Report saved: ransomware_intel_report.md")
    return report

generate_ransomware_intel_report(trends, risk, new_groups)
```## 验证标准

- 从公共跟踪源获取的勒索软件受害者数据
- 通过每月细分分析团体活动趋势
- 进行部门和地理风险评估
- 通过活动指标确定新的和正在出现的群体
- 生成带有可行建议的情报报告
- 所有收集均通过授权的公共来源进行

## 参考资料
- [Ransomwatch GitHub](https://github.com/joshhighet/ransomwatch)
- [SOCRadar：2025 年顶级勒索软件统计数据](https://socradar.io/blog/top-20-ransomware-statistics-to-know-2025/)
- [Bitsight：勒索软件和深网趋势](https://www.bitsight.com/underground/ransomware)
- [Sophos：2025 年威胁情报报告](https://www.sophos.com/en-us/blog/threat-intelligence-executive-report-volume-2025-number-6)
- [H-ISAC：勒索软件数据泄露站点报告](https://www.aha.org/h-isac-green-reports/2025-08-26-h-isac-tlp-ransomware-data-leak-sites-report-august-26-2025)
- [CYFIRMA：每周情报报告](https://www.cyfirma.com/news/weekly-intelligence-report-16-january-2026/)