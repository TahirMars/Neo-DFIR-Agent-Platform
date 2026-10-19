---
id: analyzing-azure-activity-logs-for-threats
name: analyzing-azure-activity-logs-for-threats
description: 通过 azure-monitor-query 查询 Azure 活动与登录日志，用 KQL 检测可疑管理与登录异常。
domain: cybersecurity
subdomain: security-operations
tags:
- analyzing
- azure
- activity
- logs
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 分析 Azure 活动日志以发现威胁


## 使用时机

- 在需要运用本技能进行分析的安全事件调查中
- 需要为本领域构建检测规则或威胁狩猎查询时
- SOC 分析师需要此类分析的结构化流程时
- 需要验证与相关攻击技术有关的安全监控覆盖时

## 前置条件

- 熟悉安全运营概念与工具
- 可在测试或实验环境中安全执行
- 已安装 Python 3.8+ 及所需依赖
- 具备开展测试活动的适当授权

## 说明

使用 azure-monitor-query to execute KQL queries against Azure Log Analytics workspaces,
detecting suspicious admin operations and sign-in anomalies.

```python
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient
from datetime import timedelta

credential = DefaultAzureCredential()
client = LogsQueryClient(credential)

response = client.query_workspace(
    workspace_id="WORKSPACE_ID",
    query="AzureActivity | where OperationNameValue has 'MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE' | take 10",
    timespan=timedelta(hours=24),
)
```

Key detection queries:
1. Role assignment changes (privilege escalation)
2. Resource group and subscription modifications
3. Key vault secret access from new IPs
4. Network security group rule changes
5. Conditional access policy modifications

## 示例

```python
# Detect new Global Admin role assignments
query = '''
AuditLogs
| where OperationName == "Add member to role"
| where TargetResources[0].modifiedProperties[0].newValue has "Global Administrator"
'''
```