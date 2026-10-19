---
id: hunting-for-dcom-lateral-movement
name: hunting-for-dcom-lateral-movement
name_zh: 威胁狩猎·DCOM·横向·移动
description: 通过 Sysmon 事件 ID 1（进程创建）与事件 ID 3（网络连接）关联、WMI 事件分析、135 端口 RPC 端点映射流量及 DCOM
  特有父子进程关系，检测 MMC20.Application、ShellBrowserWindow、ShellWindows 等 COM 对象的滥用，以猎杀基于
  DCOM 的横向移动。
domain: cybersecurity
subdomain: threat-hunting
tags:
- threat-hunting
- DCOM
- lateral-movement
- T1021.003
- Sysmon
- MMC20
- ShellWindows
- ShellBrowserWindow
- COM-objects
- WMI
- RPC
version: '1.0'
author: mukul975
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 威胁狩猎·DCOM·横向·移动

> **授权测试声明**：本技能所述攻击技术与模拟仅用于经系统所有者书面授权的渗透测试、红队、紫队演练与安全研究。对非自有或未获授权系统进行未授权使用属违法且不道德。请始终在授权范围内作业并遵守适用法律与法规。

## 概述

分布式组件对象模型（DCOM）通过 RPC 在网络上远程实例化并调用 COM 对象。对手滥用特定 DCOM 对象——MMC20.Application（CLSID {49B2791A-B1AE-4C90-9B8E-E860BA07F889}）、ShellBrowserWindow（CLSID {C08AFD90-F2A1-11D1-8455-00A0C91F3880}）、ShellWindows（CLSID {9BA05972-F6A8-11CF-A442-00A0C90A8F39}）——在远程主机执行命令且无需落盘，属于映射至 MITRE ATT&CK T1021.003 的隐蔽横向移动技术。本技能提供基于 Sysmon 遥测、Windows 安全事件关联、网络监控与 SIEM 检测规则识别企业环境中 DCOM 滥用的检测策略。

## 使用时机

- 在启用 DCOM 的 Active Directory 环境中主动猎杀横向移动
- 调查服务器上 mmc.exe、dllhost.exe 或 explorer.exe 可疑子进程创建告警
- 为 MITRE ATT&CK T1021.003（远程服务：分布式组件对象模型）构建检测规则
- 关联 Sysmon 事件 ID 1（进程创建）与事件 ID 3（网络连接）以追踪基于 DCOM 的命令执行链
- 审计域内 DCOM 暴露面以缩小横向移动攻击面
- 在紫队演练中验证针对 DCOM 技术的检测覆盖

**请勿用作** 基于 EDR 的横向移动检测的替代品；在未部署 Sysmon 或等效进程遥测的端点上单独使用、或不将网络层与主机层指标关联时使用。

## 前置条件

- 端点部署 Sysmon，配置采集事件 ID 1（进程创建）、3（网络连接）、7（映像加载）、10（进程访问）
- Windows 安全事件日志转发至 SIEM（事件 ID 4624、4672、4688）
- 具备关联能力的 SIEM（Splunk、Elastic、Microsoft Sentinel）
- 监控 RPC 流量（TCP 135 及动态高端口 49152–65535）
- 环境中合法 DCOM 使用的基线清单
- 了解 MITRE ATT&CK 横向移动战术（TA0008）与 T1021.003

## 工作流程

### 第 1 步：理解 DCOM 横向移动攻击向量

DCOM 横向移动主要滥用三类 COM 对象，各自具有不同取证痕迹。

**MMC20.Application**——攻击者远程实例化 MMC 管理单元并调用 `ExecuteShellCommand` 在目标上执行任意命令。目标上会出现 mmc.exe 作为 svchost.exe（DcomLaunch 服务）的子进程。

**ShellBrowserWindow**——通过 `Document.Application.ShellExecute` 在已有 explorer.exe 进程中执行命令。与 MMC20 不同，不会为 COM 服务器本身新建进程，因而更隐蔽。

**ShellWindows**——与 ShellBrowserWindow 类似，在已有 explorer.exe 实例内激活并从 explorer.exe 派生子进程。无独立 COM 服务器进程时，若无适当遥测更难检测。```powershell
# ATTACK SIMULATION (authorized testing only)
# These commands demonstrate what adversaries execute -- use only in lab environments

# MMC20.Application lateral movement
# $dcom = [System.Activator]::CreateInstance(
#     [Type]::GetTypeFromProgID("MMC20.Application", "TARGET_IP"))
# $dcom.Document.ActiveView.ExecuteShellCommand(
#     "cmd.exe", $null, "/c whoami > C:\temp\output.txt", "7")

# ShellWindows lateral movement
# $dcom = [System.Activator]::CreateInstance(
#     [Type]::GetTypeFromCLSID(
#         [guid]"9BA05972-F6A8-11CF-A442-00A0C90A8F39", "TARGET_IP"))
# $dcom.item().Document.Application.ShellExecute(
#     "cmd.exe", "/c calc.exe", "C:\windows\system32", $null, 0)

# ShellBrowserWindow lateral movement
# $dcom = [System.Activator]::CreateInstance(
#     [Type]::GetTypeFromCLSID(
#         [guid]"C08AFD90-F2A1-11D1-8455-00A0C91F3880", "TARGET_IP"))
# $dcom.Document.Application.ShellExecute(
#     "cmd.exe", "/c net user", "C:\windows\system32", $null, 0)
```### 第 2 步：为 DCOM 检测配置 Sysmon```xml
<!-- Sysmon configuration excerpt for DCOM lateral movement detection -->
<!-- Add these rules to your existing Sysmon config -->

<Sysmon schemaversion="4.90">
  <EventFiltering>

    <!-- Event ID 1: Process Creation - Detect DCOM-spawned processes -->
    <RuleGroup name="DCOM_ProcessCreate" groupRelation="or">
      <ProcessCreate onmatch="include">
        <!-- MMC20.Application: mmc.exe spawning child processes -->
        <ParentImage condition="end with">mmc.exe</ParentImage>
        <!-- DcomLaunch service spawning COM servers -->
        <ParentCommandLine condition="contains">DcomLaunch</ParentCommandLine>
        <!-- dllhost.exe spawning suspicious children -->
        <ParentImage condition="end with">dllhost.exe</ParentImage>
        <!-- explorer.exe spawning cmd/powershell (ShellWindows/ShellBrowserWindow) -->
        <Rule groupRelation="and">
          <ParentImage condition="end with">explorer.exe</ParentImage>
          <Image condition="end with">cmd.exe</Image>
        </Rule>
        <Rule groupRelation="and">
          <ParentImage condition="end with">explorer.exe</ParentImage>
          <Image condition="end with">powershell.exe</Image>
        </Rule>
      </ProcessCreate>
    </RuleGroup>

    <!-- Event ID 3: Network Connection - Track DCOM RPC connections -->
    <RuleGroup name="DCOM_NetworkConnect" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- RPC Endpoint Mapper -->
        <DestinationPort condition="is">135</DestinationPort>
        <!-- DCOM processes making network connections -->
        <Image condition="end with">mmc.exe</Image>
        <Image condition="end with">dllhost.exe</Image>
        <!-- svchost.exe DcomLaunch connections -->
        <Rule groupRelation="and">
          <Image condition="end with">svchost.exe</Image>
          <DestinationPort condition="more than">49151</DestinationPort>
        </Rule>
      </NetworkConnect>
    </RuleGroup>

    <!-- Event ID 7: Image Loaded - DCOM-related DLLs -->
    <RuleGroup name="DCOM_ImageLoaded" groupRelation="or">
      <ImageLoad onmatch="include">
        <ImageLoaded condition="end with">comsvcs.dll</ImageLoaded>
        <ImageLoaded condition="end with">ole32.dll</ImageLoaded>
        <ImageLoaded condition="end with">rpcrt4.dll</ImageLoaded>
      </ImageLoad>
    </RuleGroup>

  </EventFiltering>
</Sysmon>
```

```bash
# Deploy or update Sysmon configuration
# sysmon64.exe -c dcom-detection-sysmon.xml

# Verify Sysmon is capturing DCOM events
# PowerShell: Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 |
#   Where-Object { $_.Id -in @(1,3) } | Format-Table TimeCreated, Id, Message -Wrap
```### 第 3 步：构建针对 DCOM 对象滥用的 SIEM 检测规则```yaml
# Sigma Rule: MMC20.Application DCOM Lateral Movement
title: DCOM Lateral Movement via MMC20.Application
id: 8a3b5f2e-c1d4-4a9f-b237-1e6f8d2c3a4b
status: stable
description: >
  Detects remote instantiation of MMC20.Application DCOM object by monitoring
  for mmc.exe spawned by svchost.exe DcomLaunch service with subsequent child
  process creation, indicating T1021.003 lateral movement.
references:
    - https://attack.mitre.org/techniques/T1021/003/
    - https://www.cybereason.com/blog/dcom-lateral-movement-techniques
    - https://www.mdsec.co.uk/2020/09/i-like-to-move-it-windows-lateral-movement-part-2-dcom/
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\mmc.exe'
    selection_child:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\wscript.exe'
            - '\cscript.exe'
            - '\mshta.exe'
            - '\rundll32.exe'
            - '\regsvr32.exe'
    filter_legitimate:
        ParentCommandLine|contains:
            - 'devmgmt.msc'
            - 'diskmgmt.msc'
            - 'services.msc'
            - 'compmgmt.msc'
    condition: selection_parent and selection_child and not filter_legitimate
level: high
tags:
    - attack.lateral_movement
    - attack.t1021.003
falsepositives:
    - Legitimate remote MMC administration by authorized IT staff
    - SCCM or other management tools using DCOM for remote management
```

```yaml
# Sigma Rule: ShellWindows/ShellBrowserWindow DCOM Lateral Movement
title: DCOM Lateral Movement via ShellWindows or ShellBrowserWindow
id: 2f7c9d1e-a8b3-4c5f-9012-3e4d5f6a7b8c
status: stable
description: >
  Detects DCOM lateral movement using ShellWindows (CLSID 9BA05972) or
  ShellBrowserWindow (CLSID C08AFD90) by monitoring for explorer.exe spawning
  cmd.exe or powershell.exe on systems where no user is interactively logged on,
  or where the network logon (Type 3) precedes the process creation.
references:
    - https://attack.mitre.org/techniques/T1021/003/
    - https://www.elastic.co/guide/en/security/8.19/incoming-dcom-lateral-movement-with-shellbrowserwindow-or-shellwindows.html
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\explorer.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\mshta.exe'
            - '\wscript.exe'
            - '\cscript.exe'
    filter_interactive:
        LogonId: '0x3e7'
    condition: selection and not filter_interactive
level: medium
tags:
    - attack.lateral_movement
    - attack.t1021.003
falsepositives:
    - Users launching command prompts from Explorer context menus
    - Software installers launching child processes from explorer.exe
```

```yaml
# Sigma Rule: Sysmon Network Connection to RPC Endpoint Mapper from DCOM Process
title: DCOM Process Inbound RPC Connection Followed by Process Creation
id: 4d9e2f1a-b3c5-4a7f-8901-2c3d4e5f6a7b
status: experimental
description: >
  Correlates Sysmon Event ID 3 (Network Connection) on port 135 with
  subsequent Event ID 1 (Process Create) from DCOM parent processes
  (mmc.exe, dllhost.exe, explorer.exe) within a short time window.
logsource:
    product: windows
    service: sysmon
detection:
    network_connection:
        EventID: 3
        DestinationPort: 135
        Initiated: 'false'
    process_creation:
        EventID: 1
        ParentImage|endswith:
            - '\mmc.exe'
            - '\dllhost.exe'
            - '\svchost.exe'
    timeframe: 30s
    condition: network_connection | near process_creation
level: high
tags:
    - attack.lateral_movement
    - attack.t1021.003
```### 第 4 步：部署 Splunk 与 KQL 检测查询```spl
# Splunk: Detect MMC20.Application DCOM Lateral Movement
# Correlates network logon (4624 Type 3) with mmc.exe process creation

index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 ParentImage="*\\mmc.exe"
(Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe"
 OR Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR Image="*\\mshta.exe")
| eval target_host=ComputerName
| join target_host type=inner
    [search index=wineventlog EventCode=4624 LogonType=3
    | where AuthenticationPackageName="NTLM" OR AuthenticationPackageName="Kerberos"
    | eval target_host=ComputerName
    | rename IpAddress as source_ip, TargetUserName as logon_user
    | fields target_host source_ip logon_user _time]
| where abs(_time - relative_time(now(), "-5m")) < 300
| table _time target_host Image ParentImage CommandLine source_ip logon_user
| sort -_time
```

```spl
# Splunk: Detect ShellWindows/ShellBrowserWindow DCOM Lateral Movement
# Identifies explorer.exe spawning suspicious child processes on servers

index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 ParentImage="*\\explorer.exe"
(Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| eval target_host=ComputerName
| join target_host type=inner
    [search index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
     EventCode=3 DestinationPort=135 Initiated="false"
    | eval target_host=ComputerName
    | rename SourceIp as dcom_source_ip
    | fields target_host dcom_source_ip _time]
| where abs(_time - relative_time(now(), "-2m")) < 120
| stats count values(Image) as child_processes values(CommandLine) as commands
    by target_host dcom_source_ip
| where count > 0
| table target_host dcom_source_ip child_processes commands count
```

```spl
# Splunk: DCOM RPC Endpoint Mapper Connection Anomaly
# Identifies hosts receiving unusual volumes of inbound RPC connections

index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=3 DestinationPort=135 Initiated="false"
| stats dc(SourceIp) as unique_sources count by ComputerName
| where unique_sources > 3 OR count > 10
| sort -unique_sources
| table ComputerName unique_sources count
```

```kql
-- Microsoft Sentinel KQL: DCOM Lateral Movement via MMC20.Application

let dcom_network = SysmonEvent
| where EventID == 3
| where DestinationPort == 135
| where InitiatedConnection == false
| project NetworkTime=TimeGenerated, TargetComputer=Computer,
    SourceIP=SourceIp, DestPort=DestinationPort;

let dcom_process = SysmonEvent
| where EventID == 1
| where ParentImage endswith "\\mmc.exe"
    or ParentImage endswith "\\dllhost.exe"
| where Image endswith "\\cmd.exe"
    or Image endswith "\\powershell.exe"
    or Image endswith "\\pwsh.exe"
    or Image endswith "\\wscript.exe"
    or Image endswith "\\mshta.exe"
| project ProcessTime=TimeGenerated, TargetComputer=Computer,
    ParentImage, Image, CommandLine, User;

dcom_network
| join kind=inner (dcom_process) on TargetComputer
| where abs(datetime_diff('second', NetworkTime, ProcessTime)) < 60
| project NetworkTime, ProcessTime, TargetComputer, SourceIP,
    ParentImage, Image, CommandLine, User
| sort by NetworkTime desc
```

```kql
-- Microsoft Sentinel KQL: ShellWindows DCOM Lateral Movement

SecurityEvent
| where EventID == 4624 and LogonType == 3
| where AuthenticationPackageName in ("NTLM", "Kerberos")
| project LogonTime=TimeGenerated, TargetComputer=Computer,
    SourceIP=IpAddress, LogonUser=TargetUserName
| join kind=inner (
    SysmonEvent
    | where EventID == 1
    | where ParentImage endswith "\\explorer.exe"
    | where Image endswith "\\cmd.exe"
        or Image endswith "\\powershell.exe"
        or Image endswith "\\pwsh.exe"
    | project ProcessTime=TimeGenerated, TargetComputer=Computer,
        Image, CommandLine, User
) on TargetComputer
| where ProcessTime between (LogonTime .. (LogonTime + 2m))
| project LogonTime, ProcessTime, TargetComputer, SourceIP,
    LogonUser, Image, CommandLine
| sort by LogonTime desc
```### 第 5 步：针对 DCOM 活动的 WMI 事件关联```spl
# Splunk: Correlate WMI events with DCOM lateral movement
# WMI-Activity operational log captures DCOM-triggered WMI calls

index=wineventlog source="WinEventLog:Microsoft-Windows-WMI-Activity/Operational"
| where EventCode IN (5857, 5858, 5859, 5860, 5861)
| eval event_type=case(
    EventCode=5857, "WMI Provider Loaded",
    EventCode=5858, "WMI Query Error",
    EventCode=5859, "WMI Provider Event",
    EventCode=5860, "WMI Temporary Event Registration",
    EventCode=5861, "WMI Permanent Event Registration")
| stats count values(event_type) as wmi_events by ComputerName
| where count > 5
| table ComputerName wmi_events count
```

```powershell
# PowerShell: Query WMI operational log for DCOM-related activity
# Run on target systems during investigation

Get-WinEvent -LogName "Microsoft-Windows-WMI-Activity/Operational" -MaxEvents 500 |
    Where-Object {
        $_.Id -in @(5857, 5858, 5860, 5861) -and
        $_.Message -match "DCOM|MMC20|ShellWindows|ShellBrowserWindow"
    } |
    Select-Object TimeCreated, Id,
        @{N='Detail'; E={$_.Message.Substring(0, [Math]::Min(200, $_.Message.Length))}} |
    Format-Table -AutoSize

# Query Sysmon for DCOM parent-child process chains
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath @"
*[System[(EventID=1)]] and
*[EventData[
    (Data[@Name='ParentImage'] and
     (contains(Data[@Name='ParentImage'],'mmc.exe') or
      contains(Data[@Name='ParentImage'],'dllhost.exe')))
]]
"@ -MaxEvents 100 |
    Select-Object TimeCreated,
        @{N='ParentImage'; E={$_.Properties[20].Value}},
        @{N='Image'; E={$_.Properties[4].Value}},
        @{N='CommandLine'; E={$_.Properties[10].Value}},
        @{N='User'; E={$_.Properties[12].Value}} |
    Format-Table -AutoSize
```### 第 6 步：使用 Zeek 在网络层检测 DCOM```bash
# Zeek script for detecting DCOM lateral movement at the network level
# Monitors RPC Endpoint Mapper (port 135) and subsequent high-port connections

cat > /opt/zeek/share/zeek/site/custom-detections/dcom-lateral-movement.zeek << 'ZEEKEOF'
@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/protocols/dce-rpc

module DCOMLateralMovement;

export {
    redef enum Notice::Type += {
        DCOM_Lateral_Movement_Suspected,
        DCOM_RPC_Scan
    };

    # Threshold for unique targets receiving RPC connections from single source
    const rpc_target_threshold: count = 3 &redef;
    const rpc_time_window: interval = 10min &redef;
}

event zeek_init()
{
    local r1 = SumStats::Reducer(
        $stream="dcom.rpc_targets",
        $apply=set(SumStats::UNIQUE)
    );

    SumStats::create([
        $name="detect-dcom-lateral",
        $epoch=rpc_time_window,
        $reducers=set(r1),
        $threshold_val(key: SumStats::Key, result: SumStats::Result) = {
            return result["dcom.rpc_targets"]$unique + 0.0;
        },
        $threshold=rpc_target_threshold + 0.0,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
            NOTICE([
                $note=DCOM_RPC_Scan,
                $msg=fmt("Host %s connected to %d hosts on RPC/135 in %s - possible DCOM lateral movement",
                         key$str, result["dcom.rpc_targets"]$unique, rpc_time_window),
                $identifier=key$str
            ]);
        }
    ]);
}

event connection_state_remove(c: connection)
{
    if ( c$id$resp_p == 135/tcp && c$id$resp_h in Site::local_nets )
    {
        SumStats::observe("dcom.rpc_targets",
            [$str=cat(c$id$orig_h)],
            [$str=cat(c$id$resp_h)]
        );
    }
}
ZEEKEOF

# Monitor DCE-RPC operations related to DCOM objects
cat /opt/zeek/logs/current/dce_rpc.log | \
  zeek-cut ts id.orig_h id.resp_h endpoint operation | \
  grep -iE "IDispatch|IRemoteActivation|IRemUnknown|IObjectExporter" | \
  sort -t$'\t' -k2 | uniq -c | sort -rn

# Track RPC endpoint mapper connections between internal hosts
cat /opt/zeek/logs/current/conn.log | \
  zeek-cut ts id.orig_h id.resp_h id.resp_p duration | \
  awk '$4 == 135' | \
  awk '{print $2, "->", $3}' | sort | uniq -c | sort -rn | head -20
```### 第 7 步：DCOM 攻击面审计与加固```powershell
# Audit DCOM configuration across the domain
# Enumerate remotely accessible DCOM objects

# List DCOM applications registered on local system
Get-CimInstance -ClassName Win32_DCOMApplication |
    Select-Object AppID, Name |
    Sort-Object Name |
    Format-Table -AutoSize

# Check DCOM launch permissions for high-risk objects
$clsids = @{
    "MMC20.Application"    = "{49B2791A-B1AE-4C90-9B8E-E860BA07F889}"
    "ShellWindows"         = "{9BA05972-F6A8-11CF-A442-00A0C90A8F39}"
    "ShellBrowserWindow"   = "{C08AFD90-F2A1-11D1-8455-00A0C91F3880}"
    "Excel.Application"    = "{00024500-0000-0000-C000-000000000046}"
    "Outlook.Application"  = "{0006F03A-0000-0000-C000-000000000046}"
}

foreach ($name in $clsids.Keys) {
    $clsid = $clsids[$name]
    $regPath = "HKLM:\SOFTWARE\Classes\CLSID\$clsid"
    if (Test-Path $regPath) {
        $launchPermission = (Get-ItemProperty -Path "$regPath" -Name "LaunchPermission" -ErrorAction SilentlyContinue)
        Write-Host "[*] $name ($clsid): $(if ($launchPermission) { 'Custom permissions set' } else { 'DEFAULT permissions (potentially exploitable)' })"
    } else {
        Write-Host "[-] $name ($clsid): Not found on this system"
    }
}

# Check if DCOM is enabled (should be restricted on servers that don't need it)
$dcomEnabled = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Ole" -Name "EnableDCOM").EnableDCOM
Write-Host "`n[*] DCOM Enabled: $dcomEnabled"

# Check remote launch and activation permissions
$remoteLaunch = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Ole" -Name "DefaultLaunchPermission" -ErrorAction SilentlyContinue)
Write-Host "[*] Default Launch Permission: $(if ($remoteLaunch) { 'Custom' } else { 'System Default' })"
```

```powershell
# Hardening: Restrict DCOM remote access via Group Policy
# These settings should be applied via GPO in production

# Disable DCOM on systems that do not require it
# Computer Configuration > Administrative Templates > System > Distributed COM >
#   Application Compatibility > Enable Distributed COM on this computer = Disabled

# Restrict DCOM launch permissions via registry
# Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Ole" -Name "EnableDCOM" -Value "N"

# Block RPC/DCOM at the host firewall for non-admin traffic
# New-NetFirewallRule -DisplayName "Block Inbound DCOM/RPC" `
#     -Direction Inbound -LocalPort 135 -Protocol TCP `
#     -Action Block -RemoteAddress "Any" `
#     -Group "DCOM Hardening"
#
# New-NetFirewallRule -DisplayName "Allow DCOM from Admin Subnets" `
#     -Direction Inbound -LocalPort 135 -Protocol TCP `
#     -Action Allow -RemoteAddress "10.10.0.0/24" `
#     -Group "DCOM Hardening"

# Windows Firewall: Restrict dynamic RPC port range
# netsh int ipv4 set dynamicport tcp start=49152 num=1024
```## 关键概念

| 术语 | 定义 |
|------|------------|
| **DCOM（T1021.003）** | 分布式组件对象模型——扩展 COM 以支持经 RPC 的远程对象实例化与方法调用，常被滥用于横向移动 |
| **MMC20.Application** | 控制 MMC 管理单元的 COM 对象（CLSID {49B2791A-B1AE-4C90-9B8E-E860BA07F889}）；`ExecuteShellCommand` 方法可远程执行命令 |
| **ShellWindows** | COM 对象（CLSID {9BA05972-F6A8-11CF-A442-00A0C90A8F39}），在已有 explorer.exe 进程内激活，执行命令而无需新建 COM 服务器进程 |
| **ShellBrowserWindow** | COM 对象（CLSID {C08AFD90-F2A1-11D1-8455-00A0C91F3880}），与 ShellWindows 类似，使用 `Document.Application.ShellExecute` 隐蔽执行命令 |
| **RPC 端点映射器** | 监听 TCP 135 的服务，将 RPC 接口映射到动态端口；所有 DCOM 通信均始于端点映射器查询 |
| **Sysmon 事件 ID 1** | 进程创建事件，记录父子进程、命令行与用户上下文——识别 DCOM 派生进程的关键 |
| **Sysmon 事件 ID 3** | 网络连接事件，记录源/目的 IP 与端口——用于将 RPC 连接与后续进程创建关联 |
| **DcomLaunch** | Windows 服务（svchost.exe -k DcomLaunch），管理 DCOM 服务器进程激活；经远程 DCOM 调用所生成 COM 服务器的父进程 |
| **WMI-Activity ETW** | 记录 WMI 方法调用、实例创建与查询的 Windows 事件跟踪提供程序——提供 DCOM 触发的 WMI 操作可见性 |

## 工具与系统

| 工具 | 用途 |
|------|---------|
| **Sysmon** | 端点遥测：进程创建（EID 1）、网络连接（EID 3）、映像加载（EID 7），对 DCOM 检测至关重要 |
| **Splunk / Elastic SIEM** | 日志汇聚与关联平台，用于 DCOM 检测规则与威胁猎杀查询 |
| **Microsoft Sentinel** | 云 SIEM，内置 KQL 与分析规则用于 DCOM 横向移动检测 |
| **Sigma** | 与厂商无关的检测规则格式，便于移植 DCOM 检测规则 |
| **Zeek** | 网络安全监控，用于 DCE-RPC 协议分析与 RPC 端点映射流量监控 |
| **Atomic Red Team** | MITRE ATT&CK 测试框架，含 T1021.003 原子测试以验证 DCOM 检测覆盖 |
| **Impacket（dcomexec.py）** | 基于 Python 的 DCOM 执行工具，被攻击者与红队用于测试 DCOM 横向移动 |
| **CIMSession / PowerShell** | Windows 原生 DCOM 实例化工具，既用于合法管理也被攻击滥用 |

## 常见场景

### 场景 1：针对文件服务器的 MMC20.Application 横向移动

**背景**：SOC 分析师收到告警：文件服务器（10.10.20.50）在 03:22 UTC 出现 mmc.exe 派生 cmd.exe，该时段无计划内管理员操作。

**处理思路**：
1. 在 10.10.20.50 查询 Sysmon 事件 ID 1：确认 mmc.exe（父进程：svchost.exe -k DcomLaunch）派生 cmd.exe，命令行为 `/c net user /domain > C:\temp\users.txt`
2. 在 10.10.20.50 查询 Sysmon 事件 ID 3：03:22:01 自 10.10.5.30 的入站 TCP 135，随后在 03:22:02 出现高端口连接
3. 关联 10.10.20.50 的事件 ID 4624：03:22:00 自 10.10.5.30 的 LogonType 3 与管理凭据
4. 调查 10.10.5.30：查找沦陷指标——内存中发现 Mimikatz 痕迹，03:15 存在凭据转储证据
5. 还原攻击链：02:45 钓鱼沦陷，03:15 窃凭，03:22 DCOM 横向移动
6. 遏制：隔离 10.10.5.30 与 10.10.20.50，重置沦陷管理员密码，从非管理子网阻断入站 RPC

**易错点**：
- 未核对父进程与命令行便将 mmc.exe 活动视为合法 MMC 远程管理
- 未将网络登录（4624）与进程创建关联以定位真实源主机
- 未在源主机上排查初始沦陷指标

### 场景 2：ShellWindows 隐蔽横向移动

**背景**：威胁猎杀中分析师查询域控上 explorer.exe 派生 cmd.exe，在 DC01 发现多例，且该时间窗口无交互式登录会话。

**处理思路**：
1. 确认无交互会话：查询 DC01 上事件 ID 4624 的 LogonType 2 或 10——时间窗口内无记录
2. 查询 Sysmon 事件 ID 1：14:05、14:12、14:18 explorer.exe 派生 cmd.exe 且含编码 PowerShell
3. 解码 PowerShell：发现侦察命令（Get-ADUser、Get-ADGroup、Get-ADComputer）
4. 查询 Sysmon 事件 ID 3：每次进程创建前存在来自 10.10.3.15 的入站 RPC
5. 识别 ShellWindows 模式：未新建 mmc.exe 或 dllhost.exe——命令经已有 explorer.exe 执行，符合 ShellWindows/ShellBrowserWindow DCOM 滥用
6. 调查 10.10.3.15：沦陷工作站，存在 Cobalt Strike 信标痕迹

**易错点**：
- ShellWindows 不创建独立 COM 服务器进程——必须监控 explorer.exe 子进程，否则易漏报
- 未配置 Sysmon 事件 ID 3 采集 explorer.exe 的网络连接
- 在服务器场景下仍将 explorer.exe 一律视为合法父进程而过滤掉

## 输出格式

```
猎杀 ID: TH-DCOM-[DATE]-[SEQ]
告警严重级别: 高
MITRE 技术: T1021.003（远程服务：DCOM）

源主机: [攻击机 IP/主机名]
目标主机: [执行 DCOM 的主机 IP/主机名]
DCOM 对象: [MMC20.Application | ShellWindows | ShellBrowserWindow]
CLSID: [COM 类标识符]

进程链:
  父进程: [svchost.exe -k DcomLaunch | explorer.exe | mmc.exe]
  子进程:  [cmd.exe | powershell.exe | ...]
  命令行: [完整执行的命令]

网络指标:
  RPC 连接: [源 IP]:端口 -> [目标 IP]:135 于 [时间戳]
  DCOM 端口: [源 IP]:端口 -> [目标 IP]:[高端口] 于 [时间戳]

认证上下文:
  事件 4624: LogonType 3 来自 [源 IP] 于 [时间戳]
  账户: [域\用户名]
  登录 ID: [登录会话标识符]

风险评估: [严重/高/中]
建议动作: [隔离、调查源主机、重置凭据、限制 DCOM]
```