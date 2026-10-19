#!/usr/bin/env python3
"""
Sysmon 日志精简模块
功能：精简Sysmon日志中每条记录的内部字段，保留关键分析所需的信息
设计原则：通用性优先，不丢失重要安全分析信息
"""

from typing import List, Dict, Any, Optional


# ============================================================================
# 字段分类配置 - 可根据需求调整
# ============================================================================

# 各事件类型必须保留的核心字段 (不可精简)
ESSENTIAL_FIELDS = {
    # Event ID 1 - Process Create
    1: [
        "UtcTime", "ProcessId", "Image", "CommandLine", 
        "ParentProcessId", "ParentImage", "ParentCommandLine",
        "User", "Hashes", "CurrentDirectory"
    ],
    # Event ID 2 - File creation time changed
    2: [
        "UtcTime", "ProcessId", "Image", "TargetFilename",
        "CreationUtcTime", "PreviousCreationUtcTime", "User"
    ],
    # Event ID 3 - Network connection
    3: [
        "UtcTime", "ProcessId", "Image", "User",
        "Protocol", "Initiated",
        "SourceIp", "SourcePort",
        "DestinationIp", "DestinationPort", "DestinationPortName"
    ],
    # Event ID 4 - Sysmon service state changed
    4: [
        "UtcTime", "State", "Version"
    ],
    # Event ID 5 - Process terminated
    5: [
        "UtcTime", "ProcessId", "Image", "User"
    ],
    # Event ID 6 - Driver loaded
    6: [
        "UtcTime", "ImageLoaded", "Hashes", "Signed", "Signature"
    ],
    # Event ID 7 - Image loaded
    7: [
        "UtcTime", "ProcessId", "Image", "ImageLoaded", 
        "Hashes", "Signed", "SignatureStatus"
    ],
    # Event ID 8 - CreateRemoteThread
    8: [
        "UtcTime", "SourceProcessId", "SourceImage",
        "TargetProcessId", "TargetImage", "NewThreadId",
        "StartAddress", "StartModule", "StartFunction"
    ],
    # Event ID 9 - RawAccessRead
    9: [
        "UtcTime", "ProcessId", "Image", "Device", "User"
    ],
    # Event ID 10 - ProcessAccess
    10: [
        "UtcTime", "SourceProcessId", "SourceImage",
        "TargetProcessId", "TargetImage", 
        "GrantedAccess", "CallTrace"
    ],
    # Event ID 11 - FileCreate
    11: [
        "UtcTime", "ProcessId", "Image", "TargetFilename",
        "CreationUtcTime", "User"
    ],
    # Event ID 12 - RegistryEvent (Object create and delete)
    12: [
        "UtcTime", "ProcessId", "Image", "EventType",
        "TargetObject", "User"
    ],
    # Event ID 13 - RegistryEvent (Value Set)
    13: [
        "UtcTime", "ProcessId", "Image", "EventType",
        "TargetObject", "Details", "User"
    ],
    # Event ID 14 - RegistryEvent (Key and Value Rename)
    14: [
        "UtcTime", "ProcessId", "Image", "EventType",
        "TargetObject", "NewName", "User"
    ],
    # Event ID 15 - FileCreateStreamHash
    15: [
        "UtcTime", "ProcessId", "Image", "TargetFilename",
        "Hash", "Contents"
    ],
    # Event ID 16 - Sysmon config state changed
    16: [
        "UtcTime", "Configuration", "ConfigurationFileHash"
    ],
    # Event ID 17 - PipeEvent (Pipe Created)
    17: [
        "UtcTime", "ProcessId", "PipeName", "Image", "User"
    ],
    # Event ID 18 - PipeEvent (Pipe Connected)
    18: [
        "UtcTime", "ProcessId", "PipeName", "Image", "User"
    ],
    # Event ID 19-21 - WmiEvent
    19: [
        "UtcTime", "EventType", "Operation", "User",
        "EventNamespace", "Name", "Query"
    ],
    20: [
        "UtcTime", "EventType", "Operation", "User", "Name", "Type", "Destination"
    ],
    21: [
        "UtcTime", "EventType", "Operation", "User", "Consumer", "Filter"
    ],
    # Event ID 22 - DNSEvent (DNS query)
    22: [
        "UtcTime", "ProcessId", "Image", "QueryName",
        "QueryStatus", "QueryResults", "User"
    ],
    # Event ID 23 - FileDelete (File Delete archived)
    23: [
        "UtcTime", "ProcessId", "Image", "TargetFilename",
        "Hashes", "IsExecutable", "User"
    ],
    # Event ID 24 - ClipboardChange
    24: [
        "UtcTime", "ProcessId", "Image", "Session", "ClientInfo", "Hashes"
    ],
    # Event ID 25 - ProcessTampering
    25: [
        "UtcTime", "ProcessId", "Image", "Type", "User"
    ],
    # Event ID 26 - FileDeleteDetected
    26: [
        "UtcTime", "ProcessId", "Image", "TargetFilename", "User"
    ],
    # Event ID 27-28 - FileBlockExecutable/FileBlockShredding
    27: [
        "UtcTime", "ProcessId", "Image", "TargetFilename", "Hashes", "User"
    ],
    28: [
        "UtcTime", "ProcessId", "Image", "TargetFilename", "Hashes", "User"
    ],
    # Event ID 29 - FileExecutableDetected
    29: [
        "UtcTime", "ProcessId", "Image", "TargetFilename", "Hashes", "User"
    ],
}

# 可以移除的冗余字段 (通用)
REMOVABLE_FIELDS = [
    "FileVersion",           # 文件版本 - 通常不关键
    "Description",           # 程序描述 - 冗余
    "Product",               # 产品名 - 冗余
    "Company",               # 公司名 - 冗余
    "OriginalFileName",      # 原始文件名 - 如果Image已有则冗余
    "LogonGuid",             # 登录GUID - 通常不需要
    "LogonId",               # 登录ID - 通常不需要
    "TerminalSessionId",     # 终端会话ID - 通常不需要
    "IntegrityLevel",        # 完整性级别 - 对大多数分析不是必需的
    "ProcessGuid",           # 进程GUID - 如果有PID则通常不需要
    "ParentProcessGuid",     # 父进程GUID - 如果有父PID则通常不需要
    "RuleName",              # 规则名 - 可选
    "SourceHostname",        # 源主机名 - 如果有IP则冗余
    "SourceIsIpv6",          # IPv6标记 - 从IP可推断
    "DestinationIsIpv6",     # IPv6标记 - 从IP可推断
    "DestinationHostname",   # 目标主机名 - 如果有IP则冗余 (常为空 "-")
    "SourcePortName",        # 源端口名 - 如果有端口号则不需要
    "SchemaVersion",         # Schema版本 - 元数据,不需要
]

# 可选移除的哈希字段
HASH_FIELDS = ["Hashes", "Hash", "ConfigurationFileHash"]

# 默认跳过的事件ID (Sysmon配置/状态相关)
SKIP_EVENT_IDS = [
    4,   # Sysmon service state changed
    16,  # Sysmon config state changed
]

# 默认跳过的进程路径模式 (噪音过滤)
SKIP_IMAGE_PATTERNS = [
    # 虚拟化环境干扰
    "VBoxService.exe",      # VirtualBox Guest Additions
    "VBoxTray.exe",         # VirtualBox Tray
    
    # PowerShell 策略测试
    "__PSScriptPolicyTest", # PowerShell脚本策略测试临时文件
    
    # 系统更新与维护 (System Servicing & Updates)
    "TrustedInstaller.exe",
    "TiWorker.exe",         # Windows Modules Installer Worker
    "MoUsoCoreWorker.exe",  # Update Orchestrator
    "UsoClient.exe",        # Update Session Orchestrator
    "MusNotifyIcon.exe",    # Update Notification
    "WaaSMedicAgent.exe",   # Windows Update Medic Service
    "sihclient.exe",        # Server-Initiated Healing
    "upfc.exe",             # Update Orchestrator
    
    # 系统遥测与诊断 (Telemetry & Diagnostics)
    "wermgr.exe",           # Windows Error Reporting
    "DeviceCensus.exe",     # Telemetry
    "CompatTelRunner.exe",  # Compatibility Telemetry
    
    # 其他后台服务
    "SearchProtocolHost.exe", # Windows Search
    "SearchIndexer.exe",      # Windows Search
    "MRT.exe",                # Malicious Software Removal Tool
    "makecab.exe",            # Log compression
    "taskhostw.exe",          # Task Host
    "SppExtComObj.Exe",       # KMS/Activation
    "slui.exe",               # Activation UI
]

# 默认跳过的目标文件路径模式 (针对Event ID 11等)
SKIP_TARGET_FILENAME_PATTERNS = [
    # Windows Update 下载文件
    r"C:\Windows\SoftwareDistribution",
    
    # 系统默认计划任务
    r"C:\Windows\System32\Tasks\Microsoft\Windows",
    
    # 预取文件 (通常不关键，除非关注执行痕迹，但此处为简化)
    r"\Windows\Prefetch",
]

# 默认跳过的DNS查询名称模式 (针对Event ID 22)
SKIP_QUERY_NAME_PATTERNS = [
    # 本地/自动发现
    "wpad",
    "isatap",
    
    # 激活服务
    "_VLMCS", 
    
    # 域控制器/目录服务发现 (如果是域环境且不关注横向移动，可视为噪音)
    "_ldap._tcp",
    "_kerberos._tcp",
    "_kpasswd._tcp",
]


def parse_sysmon_message(message: str) -> dict:
    """
    解析Sysmon Message字段为字典
    Message格式: "Field1: Value1\\r\\nField2: Value2\\r\\n..."
    """
    if not message:
        return {}
    
    fields = {}
    # 先获取事件类型 (第一行)
    lines = message.split('\r\n')
    if lines:
        event_type = lines[0].rstrip(':')
        fields['_EventType'] = event_type
    
    # 解析键值对
    current_key = None
    current_value = []
    
    for line in lines[1:]:
        if not line.strip():
            continue
            
        # 检查是否是新的键值对
        if ': ' in line:
            # 保存之前的键值对
            if current_key:
                fields[current_key] = '\n'.join(current_value)
            
            # 解析新的键值对
            key, value = line.split(': ', 1)
            current_key = key.strip()
            current_value = [value]
        elif current_key:
            # 多行值的延续
            current_value.append(line)
    
    # 保存最后一个键值对
    if current_key:
        fields[current_key] = '\n'.join(current_value)
    
    return fields


def simplify_hashes(hashes: str, keep_types: list = None) -> str:
    """
    简化哈希字段，只保留指定类型
    默认只保留 SHA256
    """
    if not hashes:
        return ""
    
    if keep_types is None:
        keep_types = ["SHA256"]
    
    hash_parts = hashes.split(',')
    result = []
    
    for part in hash_parts:
        for hash_type in keep_types:
            if part.startswith(f"{hash_type}="):
                result.append(part)
                break
    
    return ','.join(result) if result else hashes


def simplify_event(event: dict, 
                   remove_empty: bool = True,
                   remove_hashes: bool = True,
                   keep_hash_types: list = None) -> dict:
    """
    精简单条Sysmon事件
    
    Args:
        event: 原始事件字典
        remove_empty: 是否移除空值字段
        remove_hashes: 是否完全移除哈希字段
        keep_hash_types: 保留的哈希类型列表
    
    Returns:
        精简后的事件字典
    """
    if keep_hash_types is None:
        keep_hash_types = ["SHA256"]
    
    result = {}
    event_id = event.get("Id")
    
    # 保留事件ID
    result["Id"] = event_id
    
    # 解析Message字段
    message = event.get("Message", "")
    parsed = parse_sysmon_message(message)
    
    # 如果Message解析为空，但Event本身包含其他字段（说明已经是解析过的格式）
    if not parsed:
        # 将原始事件作为解析结果，排除 Id 和 Message
        parsed = {k: v for k, v in event.items() if k not in ["Id", "Message"]}

    
    # 获取该事件类型应保留的字段
    essential = ESSENTIAL_FIELDS.get(event_id, [])
    
    # 处理每个解析出的字段
    for key, value in parsed.items():
        if key == '_EventType':
            result["EventType"] = value
            continue
        
        # 跳过可移除的字段
        if key in REMOVABLE_FIELDS:
            continue
        
        # 跳过空值
        if remove_empty and (not value or value == "-" or value.strip() == ""):
            continue
        
        # 完全移除哈希字段
        if remove_hashes and key in HASH_FIELDS:
            continue
        
        # 简化哈希 (当保留哈希时)
        if not remove_hashes and key in ["Hashes", "Hash"]:
            value = simplify_hashes(value, keep_hash_types)
            if not value:
                continue
        
        # 保留字段
        result[key] = value
    
    return result


def simplify_sysmon_events(events: List[Dict[str, Any]], 
                           skip_event_ids: List[int] = None,
                           skip_image_patterns: List[str] = None,
                           skip_target_filename_patterns: List[str] = None,
                           skip_query_name_patterns: List[str] = None,
                           remove_hashes: bool = True) -> List[Dict[str, Any]]:
    """
    精简Sysmon事件列表 (主接口)
    
    Args:
        events: 原始事件列表
        skip_event_ids: 跳过的事件ID列表
        skip_image_patterns: 跳过的进程路径模式
        skip_target_filename_patterns: 跳过的目标文件路径模式
        skip_query_name_patterns: 跳过的DNS查询名称模式
        remove_hashes: 是否移除哈希字段
    
    Returns:
        精简后的事件列表
    """
    if skip_event_ids is None:
        skip_event_ids = SKIP_EVENT_IDS
    
    if skip_image_patterns is None:
        skip_image_patterns = SKIP_IMAGE_PATTERNS
        
    if skip_target_filename_patterns is None:
        skip_target_filename_patterns = SKIP_TARGET_FILENAME_PATTERNS
        
    if skip_query_name_patterns is None:
        skip_query_name_patterns = SKIP_QUERY_NAME_PATTERNS
    
    def matches_pattern(text: str, patterns: List[str]) -> bool:
        if not text or not patterns:
            return False
        for pattern in patterns:
            # 简单的子字符串匹配，不分区大小写
            if pattern.lower() in text.lower():
                return True
        return False
    
    simplified_events = []
    
    for event in events:
        event_id = event.get("Id")
        message = event.get("Message", "")
        
        # 1. 过滤：基于事件ID
        if event_id in skip_event_ids:
            continue
            
        # 准备用于过滤的字段值
        image = event.get("Image")
        target_filename = event.get("TargetFilename")
        query_name = event.get("QueryName")
        
        # 如果顶层没有这些字段，且有Message，则尝试解析
        if (not image or not target_filename) and message:
             # 为了避免重复解析，这里可以简单判断或完整解析
             # 这里我们选择完整解析，因为如果通过过滤，simplify_event 也会用到
             # 但为了性能，simplify_event 会再次解析。在Python里这还可以接受。
             # 或者，我们可以检查 Message 字符串本身（作为一种近似）
             pass

        # 2. 过滤：基于Image (进程路径)
        # 优先使用提取出的 Image 字段
        if image:
            if matches_pattern(image, skip_image_patterns):
                continue
        # 其次检查 Message 字符串（针对原始日志）
        elif message and matches_pattern(message, skip_image_patterns):
            continue
            
        # 3. 过滤：基于 TargetFilename (针对文件操作)
        # 如果有 Image 已经在上面处理了，这里处理 TargetFilename
        if target_filename:
            if matches_pattern(target_filename, skip_target_filename_patterns):
                continue
        elif message:
            # 尝试从 Message 中简陋提取或匹配
            # 为准确起见，解析 Message
            parsed_preview = parse_sysmon_message(message)
            t_file = parsed_preview.get("TargetFilename")
            if t_file and matches_pattern(t_file, skip_target_filename_patterns):
                continue
            
        # 4. 过滤：基于 QueryName (针对DNS查询)
        if query_name:
            if matches_pattern(query_name, skip_query_name_patterns):
                continue
        elif message:
            parsed_preview = parse_sysmon_message(message) if 'parsed_preview' not in locals() else parsed_preview
            q_name = parsed_preview.get("QueryName")
            if q_name and matches_pattern(q_name, skip_query_name_patterns):
                continue
        
        # 如果通过了所有过滤器，进行精简
        simplified = simplify_event(event, remove_hashes=remove_hashes)
        simplified_events.append(simplified)
    
    return simplified_events
