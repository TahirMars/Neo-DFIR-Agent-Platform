---
name: hunting-advanced-persistent-threats
id: hunting-advanced-persistent-threats
description: '在企业环境中基于假设驱动，跨终端遥测、网络日志与内存工件主动搜寻高级持续性威胁（APT）活动。 适用于计划性威胁狩猎周期、调查 UEBA
  标记的异常行为，或验证环境中是否存在已知 APT TTP。 在涉及 MITRE ATT&CK、Velociraptor、osquery、Zeek 或狩猎手册的请求时启用。

  '
domain: cybersecurity
subdomain: threat-intelligence
tags:
- MITRE-ATT&CK
- threat-hunting
- APT
- Velociraptor
- osquery
- Zeek
- TTP
- NIST-CSF
- EDR
version: 1.0.0
author: mahipal
license: Apache-2.0
neo_agents:
- forensic
- report
- general_chat
---

# 狩猎高级持续性威胁（APT）

## 何时使用

在以下情况使用本技能：
- 基于新发布的 APT 情报开展主动威胁狩猎冲刺（通常 2–4 周周期）
- UEBA 或异常检测系统标记行为偏差，需要深入调查
- 同业或 ISAC 通报活跃 APT 入侵，需要验证自身暴露面

**请勿**在已确认正在发生的入侵中替代事件响应流程——应升级至 IR 规程（如 NIST SP 800-61）。

## 先决条件

- 具备 30 天以上遥测保留的 EDR（CrowdStrike Falcon、Microsoft Defender for Endpoint 或 SentinelOne）
- 可访问 MITRE ATT&CK Navigator 以构建假设
- SIEM 中可查询的网络流数据（NetFlow、Zeek 或 Suricata 日志）
- 狩猎平台或查询界面（Velociraptor、osquery 集群或 Splunk ES）

## 工作流程

### 步骤 1：形成狩猎假设

使用 MITRE ATT&CK Groups（https://attack.mitre.org/groups/）选取与行业相关的威胁组织，审阅其已知 TTP 与 ATT&CK 技术映射。示例假设：「APT29（Cozy Bear）使用带 ISO 附件的鱼叉式钓鱼（T1566.001）与离地二进制（T1218）——检测异常的 mshta.exe 与 rundll32.exe 父子关系。」

使用威胁狩猎循环框架记录假设：假设 → 数据采集 → 模式分析 → 响应。

### 步骤 2：确定所需数据源

使用 ATT&CK 数据源分类将各技术与所需日志源对应：
- 进程创建（T1059）：Windows 安全事件 4688 或 Sysmon 事件 ID 1
- 网络连接（T1071）：Zeek conn.log、NetFlow、EDR 网络遥测
- 注册表修改（T1547）：Sysmon 事件 ID 13、Windows 安全 4657
- 内存注入（T1055）：EDR 内存扫描遥测、Volatility 输出

使用 ATT&CK Coverage Calculator 或自建数据源矩阵验证日志覆盖。

### 步骤 3：使用 Velociraptor 或 osquery 执行狩猎

**Velociraptor VQL 狩猎**——异常 PowerShell 执行：
```vql
SELECT Pid, Ppid, Name, CommandLine, CreateTime
FROM pslist()
WHERE Name =~ "powershell.exe"
AND CommandLine =~ "-enc|-nop|-w hidden"
```

**osquery**——计划任务持久化：
```sql
SELECT name, action, enabled, path
FROM scheduled_tasks
WHERE action NOT LIKE '%System32%'
AND enabled = 1;
```

**Splunk SPL**——PsExec 横向移动：
```spl
index=windows EventCode=7045 ServiceFileName="*PSEXESVC*"
| stats count by ComputerName, ServiceName, ServiceFileName
```

### 步骤 4：分析结果并 pivot

对每个异常从以下维度 pivot：
- **时间**：发生在已知 IOC 时间戳之前还是之后？
- **主机**：多少终端呈现该行为？
- **用户**：关联账户是服务账户、特权用户还是普通用户？
- **网络**：主机是否与基线外的外网 IP 通信？

使用钻石模型（对手、能力、基础设施、受害者）组织发现。

### 步骤 5：记录发现并运营化

若狩猎确认恶意活动，启动 IR 流程。若未发现威胁但数据覆盖不足，记录覆盖缺口并补救。

将有效狩猎查询以 Sigma 格式转为 SIEM 检测规则，便于跨平台移植。

## 关键概念

| 术语 | 定义 |
|------|------|
| **TTP** | 战术、技术与程序——MITRE ATT&CK 中定义的对手行为模式 |
| **钻石模型** | 入侵分析框架，四个顶点为对手、能力、基础设施、受害者 |
| **Living-off-the-Land（LotL）** | 使用合法 OS 工具（PowerShell、WMI、certutil）以规避检测 |
| **UEBA** | 用户与实体行为分析——基于机器学习的异常行为基线检测 |
| **Sigma** | SIEM 无关的检测规则开放标准，类似网络/日志检测中的 YARA |
| **狩猎假设** | 基于威胁情报与环境知识、关于对手是否存在的可检验预测 |

## 工具与系统

- **Velociraptor**：开源 DFIR 平台，VQL 语言支持大规模终端狩猎
- **osquery**：基于 SQL 的 OS 插桩框架，用于实时终端遥测查询
- **MITRE ATT&CK Navigator**：Web 工具，可视化 ATT&CK 覆盖与技术优先级
- **Zeek（原 Bro）**：网络流量分析器，产出结构化日志（conn、dns、http、ssl），适合狩猎
- **Elastic Security**：EQL（事件查询语言）支持基于序列的多阶段攻击模式狩猎
- **Sigma**：检测规则格式，可翻译为 Splunk、QRadar、Sentinel、Elastic 等

## 常见误区

- **确认偏误**：带着「一定能找到」的预期狩猎，把良性数据误判为恶意。应记录空结果——它们可验证控制有效性。
- **数据保留不足**：许多 APT 技术需 90 天以上日志才能识别慢速低噪模式；默认保留往往过短。
- **无基线狩猎**：不知道「正常」就无法识别异常。狩猎前应投入时间建立基线文档。
- **查询性能影响**：业务时段对生产 SIEM 运行过宽查询可能影响分析工作流。高强度狩猎宜安排在非高峰。
- **系统性忽略误报**：按查询跟踪误报率；误报率 >80% 的规则在运营前应精炼或下线。