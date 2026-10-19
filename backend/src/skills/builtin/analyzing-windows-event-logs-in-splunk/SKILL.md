---
id: analyzing-windows-event-logs-in-splunk
name: analyzing-windows-event-logs-in-splunk
name_zh: 分析·Windows·事件·日志·Splunk
description: 通过映射到 MITRE ATT&CK 技术的 SPL 查询分析 Splunk 中的 Windows 安全、系统和 Sysmon 事件日志，以检测身份验证攻击、权限提升、持久化机制和横向移动。当
  SOC 分析师需要调查 Windows 威胁、构建检测查询或对 Windows 端点和域控制器执行取证时间线分析时使用。
domain: cybersecurity
subdomain: soc-operations
tags:
- soc
- splunk
- windows-events
- sysmon
- event-logs
- mitre-attack
- active-directory
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 分析·Windows·事件·日志·Splunk

## 使用时机
在以下场景中使用本技能：
- SOC 分析师调查与 Windows 身份验证、流程执行或 AD 更改相关的警报
- 检测工程师为基于 Windows 的威胁检测构建 SPL 查询
- 事件响应人员需要 Windows 端点或域控制器活动的取证时间表
- 定期威胁搜寻针对 Windows 特定的 ATT&CK 技术

**请勿用于 Linux/macOS 端点分析或仅网络调查。**

## 前置条件
- 摄取 Windows 事件日志数据的 Splunk（源类型“WinEventLog:Security”、“WinEventLog:System”、“XmlWinEventLog:Microsoft-Windows-Sysmon/Operational”）
- 端点上部署了具有 SwiftOnSecurity 或 Olaf Hartong 配置的 Sysmon
- 端点和身份验证数据模型的 CIM 数据模型加速
- 了解 Windows 安全事件 ID 和 Sysmon 事件类型

## 工作流程
### 第1步：认证攻击检测

**暴力检测（事件代码 4625 — 登录失败）：**```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625
| stats count, dc(TargetUserName) AS unique_users, values(TargetUserName) AS targeted_users
  by src_ip, Logon_Type, Status
| where count > 20
| eval attack_type = case(
    Logon_Type=3, "Network Brute Force",
    Logon_Type=10, "RDP Brute Force",
    Logon_Type=2, "Interactive Brute Force",
    1=1, "Other"
  )
| eval status_meaning = case(
    Status="0xc000006d", "Bad Username or Password",
    Status="0xc000006a", "Incorrect Password (valid user)",
    Status="0xc0000234", "Account Locked Out",
    Status="0xc0000072", "Account Disabled",
    1=1, Status
  )
| sort - count
| table src_ip, attack_type, status_meaning, count, unique_users, targeted_users
```**密码喷洒检测：**```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625 Logon_Type=3
| bin _time span=10m
| stats dc(TargetUserName) AS unique_users, count AS total_attempts,
  values(TargetUserName) AS users_targeted by src_ip, _time
| where unique_users > 10 AND total_attempts < unique_users * 3
| eval spray_confidence = if(unique_users > 25, "HIGH", "MEDIUM")
```**失败后成功登录（妥协指示器）：**```spl
index=wineventlog sourcetype="WinEventLog:Security"
(EventCode=4625 OR EventCode=4624) src_ip!="127.0.0.1"
| sort _time
| stats earliest(_time) AS first_seen, latest(_time) AS last_seen,
  sum(eval(if(EventCode=4625,1,0))) AS failures,
  sum(eval(if(EventCode=4624,1,0))) AS successes
  by src_ip, TargetUserName, ComputerName
| where failures > 10 AND successes > 0
| eval time_to_success = round((last_seen - first_seen)/60, 1)
| sort - failures
```### 第 2 步：权限提升检测

**新管理员账户创建 (T1136.001)：**```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4720
| join TargetUserName type=left [
    search index=wineventlog EventCode=4732 TargetUserName="Administrators"
    | rename MemberName AS TargetUserName
  ]
| table _time, SubjectUserName, TargetUserName, ComputerName
| eval alert = "New account created and added to Administrators group"
```**分配的特殊权限（事件代码 4672）：**```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4672
SubjectUserName!="SYSTEM" SubjectUserName!="LOCAL SERVICE" SubjectUserName!="NETWORK SERVICE"
| stats count, values(PrivilegeList) AS privileges by SubjectUserName, ComputerName
| where count > 0
| search privileges IN ("SeDebugPrivilege", "SeTcbPrivilege", "SeBackupPrivilege",
  "SeRestorePrivilege", "SeAssignPrimaryTokenPrivilege")
```**令牌操纵检测 (T1134)：**```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
GrantedAccess IN ("0x1010", "0x1038", "0x1fffff", "0x40")
| stats count by SourceImage, SourceUser, Computer, GrantedAccess
| where NOT match(SourceImage, "(svchost|csrss|wininit|MsMpEng|CrowdStrike)")
| sort - count
```### 第3步：持久化机制检测

**计划任务创建 (T1053.005)：**```spl
index=wineventlog (sourcetype="WinEventLog:Security" EventCode=4698)
  OR (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
      Image="*\\schtasks.exe")
| eval task_info = coalesce(TaskContent, CommandLine)
| search task_info="*powershell*" OR task_info="*cmd*" OR task_info="*http*" OR task_info="*\\Temp\\*"
| table _time, Computer, SubjectUserName, TaskName, task_info
```**注册表运行密钥修改（T1547.001）：**```spl
index=sysmon EventCode=13
TargetObject IN (
  "*\\CurrentVersion\\Run\\*",
  "*\\CurrentVersion\\RunOnce\\*",
  "*\\CurrentVersion\\RunServices\\*",
  "*\\Explorer\\Shell Folders\\*"
)
| stats count by Computer, Image, TargetObject, Details
| where NOT match(Image, "(explorer\.exe|msiexec\.exe|setup\.exe)")
| sort - count
```**WMI 事件订阅 (T1546.003)：**```spl
index=sysmon EventCode=20 OR EventCode=21
| stats count by Computer, Operation, Consumer, EventNamespace
| where count > 0
```### 第 4 步：横向移动检测

**远程服务利用（T1021.002 - SMB/Windows 管理员共享）：**```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4624 Logon_Type=3
| stats dc(ComputerName) AS unique_destinations, values(ComputerName) AS targets
  by src_ip, TargetUserName
| where unique_destinations > 3
| sort - unique_destinations
| table src_ip, TargetUserName, unique_destinations, targets
```**PsExec 检测 (T1021.002)：**```spl
index=sysmon EventCode=1
(Image="*\\psexec.exe" OR Image="*\\psexesvc.exe"
 OR ParentImage="*\\psexesvc.exe"
 OR OriginalFileName="psexec.c")
| table _time, Computer, User, ParentImage, Image, CommandLine
```**RDP 横向移动 (T1021.001)：**```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4624 Logon_Type=10
| stats count, dc(ComputerName) AS rdp_targets, values(ComputerName) AS destinations
  by src_ip, TargetUserName
| where rdp_targets > 2
| sort - rdp_targets
```### 第 5 步：构建取证时间线

为受感染的主机创建全面的时间表：```spl
(index=wineventlog OR index=sysmon) Computer="WORKSTATION-042"
earliest="2024-03-14T00:00:00" latest="2024-03-16T00:00:00"
| eval event_description = case(
    EventCode=4624, "Logon: ".TargetUserName." (Type ".Logon_Type.")",
    EventCode=4625, "Failed Logon: ".TargetUserName,
    EventCode=4688 OR (sourcetype="XmlWinEventLog:*Sysmon*" AND EventCode=1),
      "Process: ".Image." CMD: ".CommandLine,
    EventCode=4698, "Scheduled Task: ".TaskName,
    EventCode=3, "Network: ".DestinationIp.":".DestinationPort,
    EventCode=11, "File Created: ".TargetFilename,
    EventCode=13, "Registry: ".TargetObject,
    1=1, "Event ".EventCode
  )
| sort _time
| table _time, EventCode, event_description, User, src_ip
```### 第 6 步：创建丰富的查找表

为 Windows 事件 ID 上下文构建参考查找：```spl
| inputlookup windows_eventcode_lookup.csv
| table EventCode, Description, ATT_CK_Technique, Severity
```如果查找不存在，则创建它：```csv
EventCode,Description,ATT_CK_Technique,Severity
4624,Successful Logon,T1078,Informational
4625,Failed Logon,T1110,Low
4648,Explicit Credential Logon,T1078,Medium
4672,Special Privileges Assigned,T1134,Medium
4688,New Process Created,T1059,Informational
4698,Scheduled Task Created,T1053.005,Medium
4720,User Account Created,T1136.001,High
4732,Member Added to Security Group,T1098,High
4768,Kerberos TGT Requested,T1558,Informational
4769,Kerberos Service Ticket,T1558.003,Low
4771,Kerberos Pre-Auth Failed,T1110,Low
```## 关键概念

|术语 |定义|
|------|------------|
| **事件代码 4624** |成功登录事件 — Logon_Type 2（交互）、3（网络）、10（RDP）、7（解锁）|
| **事件代码 4625** |登录失败事件 — 状态代码指示失败原因（密码错误、帐户锁定、禁用）|
| **Sysmon 事件代码 1** |使用完整命令行、父进程和哈希信息创建进程 |
| **Sysmon 事件代码 3** |由进程发起的网络连接 — 源/目标 IP、端口和进程上下文 |
| **登录类型 3** |网络登录（SMB、WMI、PowerShell Remoting）——横向移动的关键指标 |
| **登录类型 10** |通过 RDP/终端服务进行远程交互式登录 |

## 工具和系统

- **Splunk Enterprise**：带有 SPL 查询引擎的 SIEM 平台，用于 Windows 事件日志分析和关联
- **Sysmon（系统监视器）**：Microsoft Sysinternals 工具提供详细的进程、网络和文件活动日志记录
- **Splunk CIM**：通用信息模型将 Windows 事件映射到跨源查询的规范化字段
- **Windows 事件转发 (WEF)**：内置 Windows 机制，用于将事件日志集中到收集器服务器

## 常见场景

- **Kerberoasting (T1558.003)**：检测非标准服务帐户的加密类型 0x17 (RC4) 的 EventCode 4769
- **DCSync (T1003.006)**：使用 DS-Replication-Get-Changes 从非 DC 源检测 EventCode 4662
- **黄金票证 (T1558.001)**：检测具有异常票证属性的 EventCode 4769（长生命周期、非标准加密）
- **传递哈希 (T1550.002)**：使用来自意外来源的 NTLM 身份验证检测 EventCode 4624 Logon_Type 3
- **DLL 侧面加载 (T1574.002)**：Sysmon EventCode 7 显示由合法进程加载的未签名 DLL

## 输出格式

```
WINDOWS EVENT LOG ANALYSIS — HOST: WORKSTATION-042
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Period:     2024-03-14 to 2024-03-15
Events:     12,847 total (Security: 9,231 | Sysmon: 3,616)

Authentication Summary:
  Successful Logons (4624):    487 (Type 3: 312, Type 10: 45, Type 2: 130)
  Failed Logons (4625):        847 (from 192.168.1.105 — BRUTE FORCE)
  Explicit Creds (4648):       12

Suspicious Findings:
  [HIGH]   847 failed logons followed by success at 14:35 from 192.168.1.105
  [HIGH]   New user "backdoor_admin" created (4720) at 14:38
  [HIGH]   User added to Administrators group (4732) at 14:38
  [MEDIUM] schtasks.exe creating persistence task at 14:42
  [MEDIUM] PowerShell encoded command execution at 14:45

ATT&CK Mapping:
  T1110.001 — Password Guessing (847 failed logons)
  T1136.001 — Local Account Creation (backdoor_admin)
  T1053.005 — Scheduled Task (persistence)
  T1059.001 — PowerShell (encoded execution)
```