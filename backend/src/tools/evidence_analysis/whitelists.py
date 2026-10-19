"""
预定义白名单数据：Windows 系统进程、服务、受信任发布者等（`evidence_analysis` 子模块）。
"""
from typing import Any

# Windows 系统进程白名单（常见系统进程）
WINDOWS_SYSTEM_PROCESSES = [
    {"process_name": "System"},
    {"process_name": "smss.exe"},
    {"process_name": "csrss.exe"},
    {"process_name": "wininit.exe"},
    {"process_name": "services.exe"},
    {"process_name": "lsass.exe"},
    {"process_name": "svchost.exe"},
    {"process_name": "lsm.exe"},
    {"process_name": "winlogon.exe"},
    {"process_name": "explorer.exe"},
    {"process_name": "spoolsv.exe"},
    {"process_name": "taskhostw.exe"},
    {"process_name": "dwm.exe"},
    {"process_name": "sihost.exe"},
    {"process_name": "RuntimeBroker.exe"},
    {"process_name": "SecurityHealthService.exe"},
    {"process_name": "MsMpEng.exe"},
    {"process_name": "SearchIndexer.exe"},
    {"process_name": "conhost.exe"},
    {"process_name": "dllhost.exe"},
    {"process_name": "msdtc.exe"},
    {"process_name": "taskmgr.exe"},
    {"process_name": "notepad.exe"},
    {"process_name": "regedit.exe"},
    {"process_name": "cmd.exe", "path": "C:\\Windows\\System32\\cmd.exe"},
    {"process_name": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
    # ... 可扩展更多
]

# Windows 系统服务白名单
WINDOWS_SYSTEM_SERVICES = [
    {"service_name": "AeLookupSvc", "display_name": "Application Experience"},
    {"service_name": "BITS", "display_name": "Background Intelligent Transfer Service"},
    {"service_name": "BrokerInfrastructure", "display_name": "Background Tasks Infrastructure Service"},
    {"service_name": "CryptSvc", "display_name": "Cryptographic Services"},
    {"service_name": "DcomLaunch", "display_name": "DCOM Server Process Launcher"},
    {"service_name": "Dhcp", "display_name": "DHCP Client"},
    {"service_name": "Dnscache", "display_name": "DNS Client"},
    {"service_name": "EventLog", "display_name": "Windows Event Log"},
    {"service_name": "EventSystem", "display_name": "COM+ Event System"},
    {"service_name": "gpsvc", "display_name": "Group Policy Client"},
    {"service_name": "iphlpsvc", "display_name": "IP Helper"},
    {"service_name": "LanmanServer", "display_name": "Server"},
    {"service_name": "LanmanWorkstation", "display_name": "Workstation"},
    {"service_name": "lmhosts", "display_name": "TCP/IP NetBIOS Helper"},
    {"service_name": "MpsSvc", "display_name": "Windows Defender Firewall"},
    {"service_name": "Netman", "display_name": "Network Connections"},
    {"service_name": "NlaSvc", "display_name": "Network Location Awareness"},
    {"service_name": "nsi", "display_name": "Network Store Interface Service"},
    {"service_name": "PlugPlay", "display_name": "Plug and Play"},
    {"service_name": "Power", "display_name": "Power"},
    {"service_name": "ProfSvc", "display_name": "User Profile Service"},
    {"service_name": "RpcSs", "display_name": "Remote Procedure Call (RPC)"},
    {"service_name": "SamSs", "display_name": "Security Accounts Manager"},
    {"service_name": "Schedule", "display_name": "Task Scheduler"},
    {"service_name": "seclogon", "display_name": "Secondary Logon"},
    {"service_name": "SENS", "display_name": "System Event Notification Service"},
    {"service_name": "Spooler", "display_name": "Print Spooler"},
    {"service_name": "SysMain", "display_name": "SysMain"},
    {"service_name": "Themes", "display_name": "Themes"},
    {"service_name": "TrustedInstaller", "display_name": "Windows Modules Installer"},
    {"service_name": "W32Time", "display_name": "Windows Time"},
    {"service_name": "Winmgmt", "display_name": "Windows Management Instrumentation"},
    {"service_name": "WinDefend", "display_name": "Windows Defender Antivirus Service"},
    {"service_name": "wuauserv", "display_name": "Windows Update"},
    # ... 可扩展更多
]

# 受信任的软件发布者白名单
TRUSTED_PUBLISHERS = [
    {"publisher": "Microsoft Corporation"},
    {"publisher": "Microsoft Windows"},
    {"publisher": "Google LLC"},
    {"publisher": "Google Inc."},
    {"publisher": "Adobe Inc."},
    {"publisher": "Adobe Systems Incorporated"},
    {"publisher": "Apple Inc."},
    {"publisher": "Mozilla Corporation"},
    {"publisher": "Oracle Corporation"},
    {"publisher": "Oracle America, Inc."},
    {"publisher": "VMware, Inc."},
    {"publisher": "Intel Corporation"},
    {"publisher": "NVIDIA Corporation"},
    {"publisher": "Realtek Semiconductor Corp."},
    # ... 可扩展更多
]

# Windows 标准服务基线（用于基线对比）
WINDOWS_BASELINE_SERVICES = WINDOWS_SYSTEM_SERVICES.copy()

# 常见启动项基线
COMMON_STARTUP_ITEMS = [
    {"name": "SecurityHealth", "location": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
    {"name": "Windows Defender", "location": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
    # ... 可扩展更多
]


def get_whitelist(name: str) -> list[dict[str, Any]]:
    """
    获取预定义白名单。
    
    参数：
        name: 白名单名称
            - "windows_system_processes"
            - "windows_system_services"
            - "trusted_publishers"
            - "windows_baseline_services"
            - "common_startup_items"
    
    返回：
        白名单项列表
    """
    whitelists = {
        "windows_system_processes": WINDOWS_SYSTEM_PROCESSES,
        "windows_system_services": WINDOWS_SYSTEM_SERVICES,
        "trusted_publishers": TRUSTED_PUBLISHERS,
        "windows_baseline_services": WINDOWS_BASELINE_SERVICES,
        "common_startup_items": COMMON_STARTUP_ITEMS,
    }
    
    whitelist = whitelists.get(name)
    if whitelist is None:
        raise ValueError(f"未知的白名单: {name}。可用: {list(whitelists.keys())}")
    
    return whitelist.copy()
