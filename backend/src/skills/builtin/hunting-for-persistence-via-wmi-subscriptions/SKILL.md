---
id: hunting-for-persistence-via-wmi-subscriptions
name: hunting-for-persistence-via-wmi-subscriptions
name_zh: 猎杀·WMI·订阅·持久化
description: 通过监控 WMI 消费者、过滤器与绑定创建事件（触发后执行恶意代码），猎杀经 Windows Management Instrumentation
  事件订阅实现的持久化（MITRE T1546.003）。
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- wmi-persistence
- mitre-t1546-003
- event-subscription
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

# 猎杀经 WMI 订阅的持久化

## 使用时机

- 在 Windows 环境中主动搜索无文件持久化
- 威胁情报称 APT 组织（如 APT29、APT32、FIN8）使用基于 WMI 的持久化
- 清理后恶意软件仍能跨重启存活时的调查
- 事件响应中常规持久化位置（Run 键、计划任务）干净但仍可疑时
- 观察到 WmiPrvSe.exe 派生意外子进程

## 前置条件

- Sysmon 事件 ID 19、20、21（WMI 事件过滤器/消费者/绑定）已启用
- Microsoft-Windows-WMI-Activity 的 Windows 事件 ID 5861
- 已启用 PowerShell 日志（脚本块、模块）
- WMI 仓库枚举访问权限
- 用于事件关联的 SIEM

## 工作流程

1. **枚举现有 WMI 订阅**：查询目标系统上所有永久 WMI 事件订阅。洁净系统通常很少或没有永久订阅，异常较易发现。
2. **监控 WMI 事件创建（Sysmon 19/20/21）**：事件 19 记录 WmiEventFilter，20 记录 WmiEventConsumer，21 记录 WmiEventConsumerToFilter 绑定。
3. **分析消费者类型**：重点关注 ActiveScriptEventConsumer（运行 VBScript/JScript）与 CommandLineEventConsumer（执行命令行）——常用于持久化的危险类型。
4. **检查事件过滤器触发条件**：审查订阅触发条件。恶意触发常包括系统启动（Win32_ProcessStartTrace）、用户登录或定时器间隔。
5. **调查 WmiPrvSe.exe 子进程**：订阅触发时由 WmiPrvSe.exe 执行动作，猎杀其异常子进程。
6. **与 MOF 编译关联**：检测使用 `mofcomp.exe` 编译 MOF 以程序化创建 WMI 订阅。
7. **验证与响应**：确认恶意订阅后删除，并回溯初始感染向量。

## 关键概念

| 概念 | 说明 |
|---------|-------------|
| T1546.003 | 事件触发执行：WMI 事件订阅 |
| __EventFilter | 定义触发条件的 WMI 类 |
| __EventConsumer | 定义执行动作的 WMI 类 |
| __FilterToConsumerBinding | 将过滤器链接到消费者 |
| ActiveScriptEventConsumer | 运行 VBScript 或 JScript 的消费者 |
| CommandLineEventConsumer | 执行命令行的消费者 |
| WmiPrvSe.exe | 执行订阅动作的 WMI 提供程序宿主 |
| MOF 文件 | 用于定义 WMI 对象的托管对象格式 |

## 检测查询

### Splunk——经 Sysmon 的 WMI 订阅创建
```spl
index=sysmon (EventCode=19 OR EventCode=20 OR EventCode=21)
| eval event_type=case(EventCode=19, "EventFilter", EventCode=20, "EventConsumer", EventCode=21, "FilterToConsumerBinding")
| table _time Computer User event_type EventNamespace Name Query Destination Operation
```

### Splunk——经 Windows 事件 5861 的 WMI 订阅
```spl
index=wineventlog source="Microsoft-Windows-WMI-Activity/Operational" EventCode=5861
| table _time Computer NamespaceName Operation PossibleCause
```

### PowerShell——枚举 WMI 订阅
```powershell
Get-WmiObject -Namespace root\subscription -Class __EventFilter
Get-WmiObject -Namespace root\subscription -Class __EventConsumer
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
```

### KQL——WmiPrvSe.exe 派生可疑子进程
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "wmiprvse.exe"
| where FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine
```

### Sigma 规则
```yaml
title: WMI Event Subscription Persistence
status: stable
logsource:
    product: windows
    category: wmi_event
detection:
    selection_consumer:
        EventID: 20
        Destination|contains:
            - 'ActiveScriptEventConsumer'
            - 'CommandLineEventConsumer'
    condition: selection_consumer
level: high
tags:
    - attack.persistence
    - attack.t1546.003
```

## 常见场景

1. **APT29 WMI 持久化**：创建 ActiveScriptEventConsumer，在系统启动时执行 VBScript 后门，跨重启与凭据重置存活。
2. **Turla WMI 后门**：Win32_ProcessStartTrace 过滤器结合 CommandLineEventConsumer 隐蔽执行命令。
3. **FIN8 WMI 定时器**：基于 __IntervalTimerEvent 每 30 分钟触发编码 PowerShell 下载。
4. **基于 MOF 的安装**：投放 .mof 并用 `mofcomp.exe` 编译以静默创建持久订阅。

## 输出格式

```
猎杀 ID: TH-WMI-[DATE]-[SEQ]
主机: [主机名]
订阅名称: [过滤器/消费者名]
过滤器查询: [WQL 触发条件]
消费者类型: [ActiveScript/CommandLine]
消费者动作: [脚本内容或命令]
绑定: [过滤器到消费者的链接]
创建时间: [时间戳]
用户上下文: [SYSTEM/用户]
风险级别: [严重/高/中/低]
```