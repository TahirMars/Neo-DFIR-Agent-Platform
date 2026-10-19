---
id: analyzing-ransomware-network-indicators
name: analyzing-ransomware-network-indicators
name_zh: 分析·勒索软件·网络·指标
description: 通过分析Zeek conn.log和NetFlow数据识别勒索软件网络行为特征，包括C2通信、TOR节点连接、数据外泄和密钥传输。适用于安全事件调查、检测规则开发和威胁监控验证场景。
domain: cybersecurity
subdomain: threat-hunting
tags:
- ransomware
- c2-beaconing
- zeek
- netflow
- tor
- exfiltration
- network-forensics
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 分析·勒索软件·网络·指标

## 概述
在勒索软件执行前及运行过程中，攻击者会建立C2通信通道、窃取敏感数据并下载加密密钥。本技能通过分析Zeek conn.log和NetFlow数据，可检测周期性信标通信（定时回调）、与已知TOR出口节点的连接行为、异常出站数据传输量以及与勒索软件相关的可疑DNS活动。

## 使用时机
- 调查需要分析勒索软件网络行为特征的安全事件时
- 构建该领域的检测规则或威胁搜寻查询语句时
- 当SOC分析师需要此类分析的标准化流程时
- 验证针对相关攻击技术的安全监控覆盖范围时

## 前置条件
- Zeek conn.log文件或NetFlow的CSV/JSON导出数据
- Python 3.8+及标准库
- TOR出口节点列表（来自Tor项目或威胁情报源）
- 可选：已知勒索软件C2的IOC列表

## 步骤

1. **解析连接日志** — 将Zeek conn.log (TSV)或NetFlow记录转换为结构化数据格式
2. **检测信标模式** — 计算连接时间间隔的统计指标（均值、标准差、变异系数）以识别周期性回调行为
3. **检查TOR出口节点连接** — 通过当前TOR出口节点列表交叉验证目标IP地址
4. **识别数据泄露** — 标记与外部IP通信时出站字节率异常偏高的连接
5. **分析DNS模式** — 检测类似DGA的域名查询行为和高熵值子域名
6. **评分和关联** — 对所有类型指标应用综合风险评分模型
7. **生成报告** — 创建包含时间线分析和MITRE ATT&CK映射的结构化报告

## 预期输出

- 包含信标检测结果和时间间隔统计的JSON格式报告
- TOR出口节点连接告警
- 数据泄露流量分析结果
- 带MITRE ATT&CK映射的复合型勒索软件风险评分（T1071、T1573、T1041）