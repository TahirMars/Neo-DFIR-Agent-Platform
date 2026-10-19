---
id: analyzing-cloud-storage-access-patterns
name: analyzing-cloud-storage-access-patterns
description: 分析 S3/GCS/Azure Blob 访问日志与审计事件，检测异常下载、新 IP 与潜在外泄。
domain: cybersecurity
subdomain: cloud-security
tags:
- analyzing
- cloud
- storage
- access
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 分析云存储访问模式


## 使用时机

- 在需要运用本技能进行分析的安全事件调查中
- 需要为本领域构建检测规则或威胁狩猎查询时
- SOC 分析师需要此类分析的结构化流程时
- 需要验证与相关攻击技术有关的安全监控覆盖时

## 前置条件

- 熟悉云安全概念与工具
- 可在测试或实验环境中安全执行
- 已安装 Python 3.8+ 及所需依赖
- 具备开展测试活动的适当授权

## 说明

1. Install dependencies: `pip install boto3 requests`
2. Query CloudTrail for S3 Data Events using AWS CLI or boto3.
3. Build access baselines: hourly request volume, per-user object counts, source IP history.
4. Detect anomalies:
   - After-hours access (outside 8am-6pm local time)
   - Bulk downloads: >100 GetObject calls from single principal in 1 hour
   - New source IPs not seen in the prior 30 days
   - ListBucket enumeration spikes (reconnaissance indicator)
5. Generate prioritized findings report.

```bash
python scripts/agent.py --bucket my-sensitive-data --hours-back 24 --output s3_access_report.json
```

## 示例

### CloudTrail S3 Data Event
```json
{"eventName": "GetObject", "requestParameters": {"bucketName": "sensitive-data", "key": "financials/q4.xlsx"},
 "sourceIPAddress": "203.0.113.50", "userIdentity": {"arn": "arn:aws:iam::123456789012:user/analyst"}}
```