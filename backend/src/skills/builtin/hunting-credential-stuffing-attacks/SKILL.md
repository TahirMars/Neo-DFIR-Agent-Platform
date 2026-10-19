---
name: hunting-credential-stuffing-attacks
id: hunting-credential-stuffing-attacks
description: '通过分析认证日志中的登录速率异常、ASN 多样性、密码喷洒模式与失败登录地理分布检测撞库攻击； 在 Splunk 或原始日志上进行统计分析。适用于调查账户接管活动或构建认证滥用的检测规则。

  '
domain: cybersecurity
subdomain: security-operations
tags:
- hunting
- credential
- stuffing
- attacks
version: '1.0'
author: mahipal
license: Apache-2.0
neo_agents:
- forensic
- general_chat
---

# 狩猎撞库（凭证填充）攻击

## 何时使用

- 需要狩猎撞库相关安全事件时
- 为该领域构建检测规则或威胁狩猎查询时
- SOC 分析师需要该分析类型的结构化流程时
- 验证与相关攻击技术的安全监控覆盖时

## 先决条件

- 熟悉安全运营概念与工具
- 可在测试或实验环境中安全执行
- 已安装 Python 3.8+ 及所需依赖
- 任何测试活动均具备适当授权

## 说明

分析认证日志，通过识别分布式登录失败、高 IP 多样性与可疑 ASN 分布等模式检测撞库。

```python
import pandas as pd
from collections import Counter

# Load auth logs
df = pd.read_csv("auth_logs.csv", parse_dates=["timestamp"])

# Credential stuffing indicator: many IPs trying few accounts
ip_per_account = df[df["status"] == "failed"].groupby("username")["source_ip"].nunique()
accounts_under_attack = ip_per_account[ip_per_account > 50]
```

主要检测指标：
1. 每个失败用户名的唯一源 IP 数量高
2. 跨多账户成功率低（< 1%）
3. 来自云/代理提供商的 ASN 集中
4. 地理不可能性（同一账户、相距极远的地点）
5. 分布式 IP 间 User-Agent 一致

## 示例

```python
# Password spray: one password tried across many accounts
spray = df[df["status"] == "failed"].groupby(["source_ip", "password_hash"]).agg(
    accounts=("username", "nunique")).reset_index()
sprays = spray[spray["accounts"] > 10]
```