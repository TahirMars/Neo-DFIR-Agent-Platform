---
id: analyzing-threat-actor-ttps-with-mitre-navigator
name: analyzing-threat-actor-ttps-with-mitre-navigator
name_zh: 分析·威胁·攻击者·TTP·MITRE·Navigator
description: 使用 ATT&CK Navigator 和 Attackcti Python 库将高级持续威胁 (APT) 团体战术、技术与程序 (TTP)
  映射到 MITRE ATT&CK 框架。分析师通过 STIX/TAXII 数据查询获取群组技术关联，生成导航器层文件进行可视化展示，并比较防御覆盖范围与对手概况。激活涉及
  APT TTP 映射、ATT&CK 导航器层、威胁参与者分析或 MITRE 技术覆盖分析的请求。
domain: cybersecurity
subdomain: threat-intelligence
tags:
- mitre-attack
- navigator
- threat-intelligence
- apt
- ttp-mapping
- stix
- attackcti
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- report
- general_chat
---

# 分析·威胁·攻击者·TTP·MITRE·Navigator

## 概述
MITRE ATT&CK Navigator 是一款用于注释和可视化 ATT&CK 矩阵的 Web 应用程序。
结合 attackcti Python 库（通过 TAXII 查询 ATT&CK STIX 数据），分析师
可以以编程方式生成映射特定威胁组 TTP 的导航器层文件，进行比较
多个小组，并评估针对已知对手的检测覆盖范围差距。


## 使用时机
- 调查需要使用 Mitre Navigator 分析威胁参与者 ttps 的安全事件时
- 为该域构建检测规则或威胁搜寻查询时
- 当 SOC 分析师需要这种分析类型的结构化程序时
- 验证相关攻击技术的安全监控覆盖范围时

## 前置条件
- 安装有 Attackcti 和 stix2 库的 Python 3.8+
- MITRE ATT&CK Navigator（Web UI 或本地实例）
- 了解 STIX 2.1 对象和关系

## 步骤

1. 使用 attackcti 查询目标威胁组的 ATT&CK STIX 数据
2. 通过 STIX 关系提取与组相关的技术
3. 生成带有技术注释的 ATT&CK Navigator 层 JSON
4. 重叠检测覆盖范围以识别差距
5. 团队审查和防守计划的导出层

## 预期输出

```json
{
  "name": "APT29 TTPs",
  "domain": "enterprise-attack",
  "techniques": [
    {"techniqueID": "T1566.001", "score": 1, "comment": "Spearphishing Attachment"},
    {"techniqueID": "T1059.001", "score": 1, "comment": "PowerShell"}
  ]
}
```