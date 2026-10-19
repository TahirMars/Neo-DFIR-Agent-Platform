---
id: analyzing-kubernetes-audit-logs
name: analyzing-kubernetes-audit-logs
description: 解析 K8s API 审计日志（JSON），检测 exec、Secret 访问、RBAC 与特权 Pod 等事件。
domain: cybersecurity
subdomain: container-security
tags:
- analyzing
- kubernetes
- audit
- logs
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 分析 Kubernetes 审计日志


## 使用时机

- 在需要运用本技能进行分析的安全事件调查中
- 需要为本领域构建检测规则或威胁狩猎查询时
- SOC 分析师需要此类分析的结构化流程时
- 需要验证与相关攻击技术有关的安全监控覆盖时

## 前置条件

- 熟悉容器安全概念与工具
- 可在测试或实验环境中安全执行
- 已安装 Python 3.8+ 及所需依赖
- 具备开展测试活动的适当授权

## 说明

解析 Kubernetes 审计日志 files (JSON lines format) to detect security-relevant
events including unauthorized access, privilege escalation, and data exfiltration.

```python
import json

with open("/var/log/kubernetes/audit.log") as f:
    for line in f:
        event = json.loads(line)
        verb = event.get("verb")
        resource = event.get("objectRef", {}).get("resource")
        user = event.get("user", {}).get("username")
        if verb == "create" and resource == "pods/exec":
            print(f"Pod exec by {user}")
```

Key events to detect:
1. pods/exec and pods/attach (shell into containers)
2. secrets access (get/list/watch)
3. clusterrolebindings creation (RBAC escalation)
4. Privileged pod creation
5. Anonymous or system:unauthenticated access

## 示例

```python
# Detect secret enumeration
if verb in ("get", "list") and resource == "secrets":
    print(f"Secret access: {user} -> {event['objectRef'].get('name')}")
```