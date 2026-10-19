---
id: analyzing-web-server-logs-for-intrusion
name: analyzing-web-server-logs-for-intrusion
name_zh: 分析·Web·服务器·日志·入侵
description: 解析 Apache 和 Nginx 访问日志以检测 SQL 注入尝试、本地文件包含、目录遍历、Web 扫描仪指纹和暴力破解模式。使用基于正则表达式的模式匹配
  OWASP 攻击特征、GeoIP 丰富源属性以及统计异常检测请求频率和响应大小异常值。
domain: cybersecurity
subdomain: security-operations
tags:
- analyzing
- web
- server
- logs
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 分析·Web·服务器·日志·入侵


## 使用时机
- 调查需要分析 Web 服务器日志是否存在入侵的安全事件时
- 为该域构建检测规则或威胁搜寻查询时
- 当 SOC 分析师需要这种分析类型的结构化程序时
- 验证相关攻击技术的安全监控覆盖范围时

## 前置条件
- 熟悉安全运营概念和工具
- 访问测试或实验室环境以安全执行
- 安装了所需依赖项的 Python 3.8+
- 任何测试活动的适当授权

## 说明

1. 安装依赖项：`pip install geoip2 user-agents`
2. 以组合日志格式（Apache）或 Nginx 默认格式收集 Web 服务器访问日志。
3. 解析每个日志条目，提取：IP、时间戳、方法、URI、状态代码、响应大小、用户代理、引用者。
4. 应用检测规则：
   - SQL 注入：`UNION SELECT`、`OR 1=1`、`' OR '`、十六进制编码模式
   - LFI/路径遍历：`../`、`/etc/passwd`、`/proc/self`、`php://filter`
   - XSS：`<script>`、`javascript:`、`onerror=`、`onload=`
   - 扫描仪签名：nikto、sqlmap、dirbuster、gobuster、wfuzz 用户代理
   - 暴力破解：5 分钟内超过 50 个 POST 请求从同一 IP 登录端点
5. 丰富 GeoIP 数据并生成优先排序的调查结果报告。```bash
python scripts/agent.py --log-file /var/log/nginx/access.log --geoip-db GeoLite2-City.mmdb --output web_intrusion_report.json
```## 示例

### 检测 URI 中的 SQLi

```
192.168.1.100 - - [15/Jan/2024:10:30:45 +0000] "GET /products?id=1' UNION SELECT username,password FROM users-- HTTP/1.1" 200 4532
```### 扫描仪用户代理检测```
Nikto/2.1.6, sqlmap/1.7, DirBuster-1.0-RC1, gobuster/3.1.0
```