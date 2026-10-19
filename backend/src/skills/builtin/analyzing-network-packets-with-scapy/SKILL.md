---
id: analyzing-network-packets-with-scapy
name: analyzing-network-packets-with-scapy
name_zh: 分析·网络·数据包·Scapy
description: 使用 Scapy 进行网络数据包操作，包括构建、发送、嗅探和解析，用于协议分析、网络侦察和流量异常检测。涵盖 TCP/UDP/ICMP 数据包构建、pcap
  文件分析、协议字段提取、SYN 扫描实现、DNS 查询分析及异常流量模式识别等安全任务。
domain: cybersecurity
subdomain: network-security
tags:
- scapy
- packet-analysis
- network-forensics
- protocol-dissection
- pcap
- traffic-analysis
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 分析·网络·数据包·Scapy

## 概述
Scapy 是一个 Python 数据包操作库，能够在协议层构建、发送、嗅探和解析网络数据包。该技能涵盖使用 Scapy 执行安全相关任务，包括 TCP/UDP/ICMP 数据包构建、pcap 文件分析、协议字段提取、SYN 扫描实现、DNS 查询分析，以及检测异常流量模式（如异常碎片化数据包或格式错误的报头）。

## 使用时机
- 在调查需要 Scapy 分析网络数据包的安全事件时
- 在构建此领域的检测规则或威胁狩猎查询时
- 当 SOC 分析人员需要此类分析的结构化流程时
- 在验证相关攻击技术的安全监控覆盖范围时

## 前置条件
- 安装 Python 3.8+ 及 `scapy` 库（`pip install scapy`）
- root/管理员权限以执行原始套接字操作（嗅探、发送）
- Npcap（Windows）或 libpcap（Linux）用于数据包捕获
- 被授权在目标网络上执行数据包操作

## 步骤

1. 使用 `rdpcap()` 读取和解析 pcap/pcapng 文件进行离线分析
2. 提取协议层（IP、TCP、UDP、DNS、HTTP）和字段值
3. 计算流量统计：主要通信方、协议分布、端口频率
4. 通过分析 TCP 标志位比例检测 SYN 洪水模式
5. 通过查询长度和熵值分析识别 DNS 数据外泄指标
6. 构建自定义探测数据包用于授权网络测试
7. 将发现结果导出为结构化 JSON 报告

## 预期输出

包含数据包统计、协议分布、主要源/目的 IP、检测到的异常（SYN 洪水、DNS 隧道指示器、碎片化攻击）及每条流摘要的 JSON 报告。