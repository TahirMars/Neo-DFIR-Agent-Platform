---
id: analyzing-cyber-kill-chain
name: analyzing-cyber-kill-chain
description: 按 Lockheed Martin 杀伤链映射入侵阶段，并结合 MITRE ATT&CK 做技术与防御行动方案分析。
domain: cybersecurity
subdomain: threat-intelligence
tags:
- kill-chain
- Lockheed-Martin
- MITRE-ATT&CK
- intrusion-analysis
- defense-in-depth
- NIST-CSF
version: 1.0.0
author: team-cybersecurity
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- report
- general_chat
---

# 分析网络杀伤链

## 使用时机

在以下场景使用本技能：
- 进行事件后分析，以确定攻击者在攻击序列中推进了多远
- 设计分层防御控制，目标是在尽可能早的阶段中断攻击
- 编写威胁情报报告，向非技术利益相关者传达攻击进展

**请勿将**本技能作为独立框架单独使用 — 需与 MITRE ATT&CK 结合，以获得超出 7 阶段杀伤链的技术级细粒度。

## 前置条件

- 完整事件时间线，含已映射到具体攻击者行为的取证工件
- MITRE ATT&CK 企业矩阵，用于各杀伤链阶段内的技术级映射
- 可访问疑似攻击者组织典型杀伤链进展的威胁情报
- 响应团队提供的事件后报告或 IR 时间线

## 工作流程

### 第 1 步：将观察到的行为映射到杀伤链阶段

Lockheed Martin 杀伤链包含七个阶段。将所有观察到的攻击者行为进行映射：

**阶段 1 - 侦察**：攻击者在攻击前收集目标信息。
- 指标：攻击者 IP 的 DNS 查询、LinkedIn 数据抓取、职位发布分析、组织基础设施的 Shodan 扫描

**阶段 2 - 武器化**：攻击者创建攻击工具（恶意软件 + 漏洞利用）。
- 指标：恶意软件编译时间戳、漏洞利用文档元数据、恶意样本中的构建器工件

**阶段 3 - 交付**：攻击者将武器传递给目标。
- 指标：钓鱼邮件、恶意附件、网页挂马、U 盘投递、供应链破坏

**阶段 4 - 漏洞利用**：攻击者利用漏洞执行代码。
- 指标：应用/操作系统日志中的 CVE 利用事件、内存破坏工件、shellcode 执行

**阶段 5 - 安装**：攻击者在目标上建立持久化。
- 指标：新计划任务、注册表运行键、服务安装、Web Shell、bootkit

**阶段 6 - 命令与控制（C2）**：攻击者与被入侵系统通信。
- 指标：信标流量（规律间隔）、DNS 隧道、指向非常见域名的 HTTPS、C2 框架特征（Cobalt Strike、Sliver）

**阶段 7 - 目标行动**：攻击者达成目标。
- 指标：数据准备/外泄、横向移动、勒索软件执行、破坏性活动

### 第 2 步：识别阶段完成情况及检测点

为事件建立阶段矩阵：
```
Phase 1: Recon        → Completed (undetected)
Phase 2: Weaponize    → Completed (undetected — pre-attack)
Phase 3: Delivery     → Completed; phishing email bypassed SEG
Phase 4: Exploit      → Completed; CVE-2023-23397 exploited
Phase 5: Install      → DETECTED: EDR flagged scheduled task creation (attack stalled here)
Phase 6: C2           → Not achieved (installation blocked)
Phase 7: Objectives   → Not achieved
```

对每个在未被检测情况下完成的阶段，记录防御控制缺口。

### 第 3 步：映射到 MITRE ATT&CK 获取技术细节

每个杀伤链阶段对应多个 ATT&CK 战术：
- 交付 → 初始访问（TA0001）
- 漏洞利用 → 执行（TA0002）
- 安装 → 持久化（TA0003）、权限提升（TA0004）
- C2 → 命令与控制（TA0011）
- 目标行动 → 数据外泄（TA0010）、影响（TA0040）

在各阶段内枚举观察到的具体 ATT&CK 技术，并映射到现有检测能力。

### 第 4 步：按阶段识别行动方案（COA）

对每个阶段记录适用的防御行动方案（Courses of Action）：
- **检测 COA**：何种检测可在该阶段对攻击者活动告警？
- **拒绝 COA**：何种控制可阻止攻击者完成该阶段？
- **扰乱 COA**：何种控制可在阶段中途打断攻击者？
- **削弱 COA**：何种控制可降低攻击者在该阶段的有效性？
- **欺骗 COA**：何种欺骗（蜜罐、金丝雀令牌）可在该阶段暴露活动？
- **摧毁 COA**：何种主动防御能力可中和攻击者基础设施？

### 第 5 步：输出杀伤链分析报告

将发现组织为：
1. 攻击叙事（按阶段的时间线）
2. 分阶段分析与证据
3. 检测点分析（哪些有效、哪些失效）
4. 按成本/效果排序的各阶段防御建议
5. 控制改进路线图

## 关键概念

| 术语 | 定义 |
|------|-----------|
| **杀伤链（Kill Chain）** | 对手入侵阶段的顺序模型；理论上打断任一环节即可阻止攻击 |
| **行动方案（COA）** | 映射到各杀伤链阶段的防御响应：检测、拒绝、扰乱、削弱、欺骗、摧毁 |
| **信标（Beaconing）** | 被控主机向 C2 服务器周期性回连的模式；可通过频率分析检测 |
| **阶段完成** | 攻击者成功结束某一杀伤链阶段并进入下一阶段；纵深防御旨在阻止其发生 |
| **情报得失** | 分析在较晚阶段（相对较早阶段）检测是否减少了对攻击者能力或意图的情报获取 |

## 工具与系统

- **MITRE ATT&CK Navigator**：将杀伤链阶段与 ATT&CK 技术覆盖叠加分析
- **Elastic Security EQL**：在 Elastic SIEM 中查询跨阶段攻击序列的事件查询语言
- **Splunk ES**：杀伤链阶段序列的时间线与关联搜索
- **MISP**：通过 galaxy 集群进行杀伤链标记，结构化记录事件

## 常见陷阱

- **线性假设**：攻击者不一定线性推进 — 可能跳过阶段（武器化在前期行动中已完成）或回环（检测后重建 C2）。
- **忽视阶段 1 与 2**：侦察与武器化在防御方可见性出现之前发生；有关这些阶段的情报需来自外部来源（OSINT、威胁情报）。
- **忽略内部威胁**：杀伤链主要针对外部对手；内部威胁可能直接跳到阶段 7 而不经过前面阶段。
- **与 ATT&CK 战术混淆**：7 阶段杀伤链与 14 个 ATT&CK 战术互补但不等价，需保持区分以免分析混乱。