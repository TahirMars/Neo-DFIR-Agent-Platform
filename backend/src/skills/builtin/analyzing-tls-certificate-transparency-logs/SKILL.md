---
id: analyzing-tls-certificate-transparency-logs
name: analyzing-tls-certificate-transparency-logs
name_zh: 分析·TLS·证书·透明·日志
description: 通过 crt.sh 和 pycrtsh 查询证书透明度日志，以检测网络钓鱼域、未经授权的证书颁发和影子IT。使用 Levenshtein
  距离监控新颁发的证书是否有误植和品牌假冒行为。用于主动网络钓鱼域检测和证书监控。
domain: cybersecurity
subdomain: security-operations
tags:
- analyzing
- tls
- certificate
- transparency
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 分析·TLS·证书·透明·日志


## 使用时机
- 调查需要分析 tls 证书透明度日志的安全事件时
- 为该域构建检测规则或威胁搜寻查询时
- 当 SOC 分析师需要这种分析类型的结构化程序时
- 验证相关攻击技术的安全监控覆盖范围时

## 前置条件
- 熟悉安全运营概念和工具
- 访问测试或实验室环境以安全执行
- 安装了所需依赖项的 Python 3.8+
- 任何测试活动的适当授权

## 说明

查询crt.sh证书透明度数据库以查找颁发的证书
与您组织的品牌相似的域名，检测网络钓鱼基础设施。```python
from pycrtsh import Crtsh

c = Crtsh()
# Search for certificates matching a domain
certs = c.search("example.com")
for cert in certs:
    print(cert["id"], cert["name_value"])

# Get full certificate details
details = c.get(certs[0]["id"], type="id")
```关键分析步骤：
1. 查询 crt.sh 以获取与您的域模式匹配的所有证书
2. 识别具有误植变异的证书（Levenshtein 距离）
3. 标记来自意外 CA 的证书
4. 监控可疑子域上的通配符证书
5. 与已知网络钓鱼基础设施的交叉引用

## 示例

```python
from pycrtsh import Crtsh
c = Crtsh()
certs = c.search("%.example.com")
for cert in certs:
    print(f"Issuer: {cert.get('issuer_name')}, Domain: {cert.get('name_value')}")
```