---
id: hunting-for-suspicious-scheduled-tasks
name: hunting-for-suspicious-scheduled-tasks
name_zh: 猎杀·可疑·计划任务
description: 通过分析任务创建事件、可疑任务属性与异常执行模式，猎杀滥用 Windows 计划任务实现的持久化与执行（MITRE T1053.005）。
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- scheduled-tasks
- persistence
- mitre-t1053-005
- windows
- endpoint-detection
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 猎杀可疑计划任务

## 使用时机

- 在 Windows 环境中主动猎杀持久化机制
- 进程创建日志中出现 schtasks.exe 或 at.exe 使用
- 调查跨重启与用户注销仍存活的恶意软件
- 事件响应中枚举沦陷系统上的全部持久化
- Windows 安全事件 ID 4698（计划任务已创建）对异常任务触发

## 前置条件

- Windows 安全事件 ID 4698/4699/4702（任务已创建/已删除/已更新）
- Sysmon 事件 ID 1 记录 schtasks.exe 进程创建及命令行
- Windows 任务计划程序操作日志（Microsoft-Windows-TaskScheduler/Operational）
- PowerShell 日志记录 Register-ScheduledTask 使用
- 端点上任务计划程序 XML 定义访问权限

## 工作流程

1. **枚举全部计划任务**：使用 `schtasks /query /fo CSV /v` 或 `Get-ScheduledTask` 从目标系统收集完整任务清单。
2. **监控任务创建事件**：跟踪事件 ID 4698，与创建进程及用户上下文关联。
3. **分析任务操作**：审查每个任务执行的内容。标记运行脚本（PowerShell、cmd、wscript）、从用户可写路径（TEMP、AppData、Downloads）运行二进制或编码/混淆命令的任务。
4. **检查任务触发器**：审查触发条件。系统启动、用户登录或短间隔（1–5 分钟）触发需重点调查。
5. **识别隐藏或伪装任务**：猎杀名称模仿合法 Windows 任务、通过修改安全描述符隐藏、或存放在非标准注册表位置的任务。
6. **与进程执行关联**：将计划任务执行事件与进程创建日志匹配，确认实际运行内容。
7. **基线与差异**：将当前任务清单与已知良好基线比对，识别新增、修改或意外任务。

## 检测查询

### Splunk——计划任务创建
```spl
index=wineventlog EventCode=4698
| spath output=TaskName path=EventData.TaskName
| spath output=TaskContent path=EventData.TaskContent
| where NOT match(TaskName, "(?i)(\\\\Microsoft\\\\|\\\\Windows\\\\)")
| table _time Computer SubjectUserName TaskName TaskContent
```

### Splunk——schtasks.exe 可疑使用
```spl
index=sysmon EventCode=1 Image="*\\schtasks.exe"
| where match(CommandLine, "(?i)/create")
| where match(CommandLine, "(?i)(powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|http|https|\\\\temp\\\\|\\\\appdata\\\\)")
| table _time Computer User CommandLine ParentImage
```

### KQL——Microsoft Sentinel
```kql
SecurityEvent
| where EventID == 4698
| extend TaskName = tostring(EventData.TaskName)
| extend TaskContent = tostring(EventData.TaskContent)
| where TaskContent has_any ("powershell", "cmd.exe", "wscript", "http://", "https://", "\\Temp\\", "\\AppData\\")
| project TimeGenerated, Computer, Account, TaskName, TaskContent
```

## 常见场景

1. **Cobalt Strike 持久化**：经 schtasks.exe 创建任务，在用户登录间隔执行 PowerShell 下载 cradle。
2. **勒索软件暂存**：创建在将来某时运行加密载荷的任务，常选非工作时间以扩大影响。
3. **经 SD 修改隐藏任务**：攻击者修改计划任务安全描述符，使其在常规枚举中不可见但仍执行。
4. **COM 处理程序滥用**：任务使用 COM 处理程序而非直接可执行路径，增加操作审查难度。
5. **经任务横向移动**：使用 `schtasks /create /s REMOTE_HOST` 在远程系统创建任务执行。

## 输出格式

```
猎杀 ID: TH-SCHTASK-[DATE]-[SEQ]
主机: [主机名]
任务名称: [完整任务路径]
操作: [执行的命令/脚本]
触发器: [启动/登录/定时器/事件]
创建者: [用户账户]
创建来源: [本地/远程]
创建时间: [时间戳]
运行身份: [执行账户]
风险级别: [严重/高/中/低]
```