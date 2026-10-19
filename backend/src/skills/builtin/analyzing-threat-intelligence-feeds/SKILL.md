---
id: analyzing-threat-intelligence-feeds
name: analyzing-threat-intelligence-feeds
name_zh: 分析·威胁·情报·情报源
description: 分析结构化和非结构化威胁情报源以提取可操作指标、对手策略及活动背景。适用于摄取商业或开源CTI源、评估源质量、标准化为STIX 2.1格式或通过活动归因丰富现有IOC。可触发ThreatConnect、Recorded
  Future等平台的自动化聚合管道。
domain: cybersecurity
subdomain: threat-intelligence
tags:
- STIX
- TAXII
- MITRE-ATT&CK
- IOC
- ThreatConnect
- Recorded-Future
- MISP
- CTI
- NIST-CSF
version: 1.0.0
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- report
- general_chat
---

# 分析·威胁·情报·情报源

## 使用时机
在以下场景中使用本技能：
- 获取新的商业或开源威胁情报源并评估其信噪比
- 将异构IOC格式（STIX 2.1、OpenIOC、YARA、Sigma）标准化为统一模式
- 评估源的新鲜度、保真度与组织威胁概况的相关性
- 构建自动化丰富管道将IOC与SIEM事件关联

**请勿在未首先建立CTI基线的情况下**使用此技能进行原始数据包捕获分析或实时事件分类。

## 前置条件
- 威胁情报平台(TIP)访问权限，如ThreatConnect、MISP或OpenCTI
- 至少一个商业源的API密钥（Recorded Future、Mandiant Advantage或VirusTotal Enterprise）
- TAXII 2.1客户端库（taxii2-client Python包或同等版本）
- 对TIP指标数据库具有读/写权限的角色

## 工作流程
### 第1步：枚举并确定Feed来源的优先级

列出按类型（商业、政府、ISAC、OSINT）分类的所有可用源：
- 商业：Recorded Future、Mandiant Advantage、CrowdStrike Falcon Intelligence
- 政府：CISA AIS（自动指标共享）、FBI InfraGard、MS-ISAC
- OSINT：AlienVault OTX、Abuse.ch、PhishTank、新兴威胁

对每个提要进行评分：更新频率、历史准确率、行业覆盖范围及归因深度。使用符合NIST SP 800-150（网络威胁信息共享指南）标准的加权评分矩阵。

### 第2步：通过TAXII 2.1或API摄取

对于启用TAXII的源：```
taxii2-client discover https://feed.example.com/taxii/
taxii2-client get-collection --collection-id <id> --since 2024-01-01
```对于REST API源（如Recorded Future）：
- 使用“risk_score_min=65”查询“/v2/indicator/search”以过滤低置信度IOC
- 应用速率限制和指数退避以实现API弹性

### 第3步：标准化为STIX 2.1

使用OASIS标准模式将每个IOC转换为STIX 2.1对象：
- IP地址 → `indicator`对象，带有`pattern: "[ipv4-addr:value = '...']"`
- 域 → `indicator` with `pattern: "[domain-name:value = '...']"`
- 文件哈希→带有“模式：“[file:hashes.SHA-256 = '...']”的“指示器”

附加将指示器链接到“威胁参与者”或“恶意软件”对象的“关系”对象。根据源保真度评级使用“置信度”字段(0–100)。

### 第4步：去重和丰富

使用规范化值+类型作为复合键对现有TIP数据库运行重复数据删除。丰富幸存的国际石油公司：
- VirusTotal：检测率、沙箱行为报告
- PassiveTotal (RiskIQ)：WHOIS历史记录、被动DNS、SSL证书链
- Shodan：横幅数据、开放端口、地理位置

### 第5步：分发到消费系统

通过TAXII 2.1推送将丰富指标导出到SIEM（Splunk、Microsoft Sentinel）、防火墙（Palo Alto XSOAR playbook）和EDR平台。设置每类指标的TTL（生存时间）：IP地址30天，域90天，文件哈希1年。

## 关键概念

|术语 |定义|
|------|------------|
| **STIX 2.1** |结构化威胁信息表达 — CTI对象的OASIS标准JSON模式，包含指标、威胁参与者、活动和关系|
| **TAXII 2.1** |可信情报信息自动交换 — 基于HTTPS的协议，用于服务器与客户端间共享STIX内容|
| **国际奥委会** |妥协指标 — 可观察工件（IP、域、哈希值、URL），表明系统可能被破坏|
| **TLP** |交通灯协议 — 颜色编码分类（红色/琥珀色/绿色/白色）定义CTI共享限制|
| **置信度分数** |反映生产者对指标恶意归因确定性的数值（STIX中为0–100）|
| **饲料保真度** |通过生产检测中真阳性率衡量饲料的历史准确率|

## 工具和系统

- **ThreatConnect TC Exchange**：聚合100多个商业和开源情报源；提供IOC丰富自动化剧本
- **MISP（恶意软件信息共享平台）**：支持STIX/TAXII的开源TIP；被ISAC和政府CERT广泛使用
- **OpenCTI**：具有本机MITRE ATT&CK集成和基于图形的关系可视化开源平台
- **记录未来**：具备AI驱动风险评分和实时暗网监控的商业信息流
- **taxii2-client**：用于TAXII 2.0/2.1客户端操作的Python库（pip install taxii2-client）
- **PyMISP**：用于MISP源管理和IOC提交的Python API

## 常见陷阱

- **IOC年龄陈旧**：IP地址和域名频繁轮换；应用1年以上的IOC会产生误报。执行TTL策略。
- **缺少上下文**：在不了解相关活动或对手的情况下阻止IOC可能破坏合法业务流量（如与恶意行为者共享的CDN IP）。
- **未进行重复数据删除的馈送重叠**：从五个未去重的馈送中提取相同IOC会增加指标计数和SIEM规则复杂性。
- **TLP违规**：在授权边界外重新分发RED机密情报违反共享协议和信任关系。
- **对低置信度指标进行过度阻止**：置信度低于50的指标应触发仅检测规则，而非阻止，以避免操作中断。