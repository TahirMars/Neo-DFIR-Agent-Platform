---
id: analyzing-threat-landscape-with-misp
name: analyzing-threat-landscape-with-misp
name_zh: 分析·威胁·全景·MISP
description: 使用MISP（恶意软件信息共享平台）通过查询事件统计数据、属性分布、威胁参与者星系集群和标签随时间变化的趋势来分析威胁态势。使用PyMISP提取事件数据、计算IOC类型分布、识别顶级威胁参与者和恶意软件家族，并生成具有时间趋势的威胁态势报告。
domain: cybersecurity
subdomain: threat-intelligence
tags:
- analyzing
- threat
- landscape
- with
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- report
- general_chat
---

# 分析·威胁·全景·MISP

## 使用时机
- 调查需要使用MISP分析威胁态势的安全事件时
- 为该域构建检测规则或威胁搜寻查询时
- 当SOC分析师需要这种分析类型的结构化程序时
- 验证相关攻击技术的安全监控覆盖范围时

## 前置条件
- 熟悉威胁情报概念和工具
- 访问测试或实验室环境以安全执行
- 安装了所需依赖项的Python 3.8+
- 任何测试活动的适当授权

## 说明

1. 安装依赖项：`pip install pymisp`
2. 配置MISP URL和API密钥。
3. 运行代理以生成威胁态势分析：
   - 按威胁级别和日期范围提取事件统计信息
   - 分析属性类型分布（IP、域、哈希、URL）
   - 从事件标签中识别顶级MITRE ATT&CK技术
   - 通过星系团跟踪威胁者活动
   - 生成IOC提交的时间趋势分析```bash
python scripts/agent.py --misp-url https://misp.local --api-key YOUR_KEY --days 90 --output landscape_report.json
```

## 示例

### 威胁概况摘要

```
Period: Last 90 days
Events analyzed: 1,247
Top threat level: High (43%)
Top attribute type: ip-dst (31%), domain (22%), sha256 (18%)
Top MITRE technique: T1566 Phishing (89 events)
Top threat actor: APT28 (34 events)
```