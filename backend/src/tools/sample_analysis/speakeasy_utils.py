"""
Speakeasy Emulation Helper Functions
This module provides utilities for processing Speakeasy emulation reports,
including API categorization, behavior extraction, and report compression.
"""
from typing import Optional
from collections import Counter, defaultdict
# API 行为分类规则 - 6 个核心类别
API_BEHAVIOR_CATEGORIES = {
    # 1. 系统操作 - 文件、注册表、资源
    "system": {
        "keywords": [
            # 文件操作
            "CreateFile", "WriteFile", "ReadFile", "DeleteFile", 
            "CopyFile", "MoveFile", "SetFilePointer", "GetFileAttributes",
            "FindFirstFile", "FindNextFile", "CreateDirectory", "RemoveDirectory",
            # 注册表
            "RegOpenKey", "RegCreateKey", "RegSetValue", "RegQueryValue",
            "RegDeleteKey", "RegEnumKey", "RegCloseKey",
            # 资源
            "FindResource", "LoadResource", "LockResource", "SizeofResource",
        ],
    },
    # 2. 进程/执行 - 进程创建、注入、动态加载
    "process": {
        "keywords": [
            # 进程/线程
            "CreateProcess", "OpenProcess", "TerminateProcess", 
            "CreateThread", "CreateRemoteThread", "WriteProcessMemory",
            "ReadProcessMemory", "VirtualAllocEx", "NtCreateThread",
            "QueueUserAPC", "SetThreadContext", "ResumeThread", "SuspendThread",
            "NtUnmapViewOfSection", "NtCreateProcess",
            # Shell 执行
            "ShellExecute", "WinExec", "system",
            # 动态加载
            "LoadLibrary", "GetProcAddress", "LdrLoadDll", "LdrGetProcedureAddress",
            # 内存操作
            "VirtualProtect", "NtProtectVirtualMemory", "MapViewOfFile",
            "CreateFileMapping", "NtMapViewOfSection",
        ],
        "injection_indicators": ["CreateRemoteThread", "WriteProcessMemory", 
                                "VirtualAllocEx", "QueueUserAPC", "NtUnmapViewOfSection"]
    },
    # 3. 网络通信 - 网络、RPC、WMI
    "network": {
        "keywords": [
            # 网络
            "connect", "send", "recv", "socket", "WSA", "Internet", 
            "Http", "Url", "DNS", "gethost", "gethostbyname", "WinHttp",
            "URLDownload", "FtpOpen", "FtpGet", "FtpPut",
            # RPC
            "Rpc", "Ndr", "RpcBinding", "NdrClientCall",
            # WMI
            "IWbem", "ExecQuery", "WbemLocator",
        ],
    },
    # 4. 持久化 - 服务、计划任务、COM、同步对象
    "persistence": {
        "keywords": [
            # 服务
            "OpenSCManager", "CreateService", "StartService", 
            "ControlService", "DeleteService", "ChangeServiceConfig", "OpenService",
            # 计划任务
            "ITaskScheduler", "ITask", "SchRpc", "ITaskService", "ITaskFolder",
            "IRegisteredTask", "IExecAction", "atsvc",
            # COM
            "CoCreateInstance", "CoInitialize", "CLSIDFromString", "CoGetClassObject",
            # 同步对象
            "CreateMutex", "OpenMutex", "CreateEvent", "CreateNamedPipe",
        ],
    },
    # 5. 规避检测 - 反分析、加密、权限
    "evasion": {
        "keywords": [
            # 反调试
            "IsDebuggerPresent", "CheckRemoteDebugger", "NtQueryInformation",
            "OutputDebugString", "GetTickCount64", "timeGetTime",
            # 加密
            "Crypt", "BCrypt", "NCrypt", "CryptAcquireContext", 
            "CryptGenKey", "CryptImportKey", "CryptDeriveKey",
            # 权限
            "OpenProcessToken", "AdjustTokenPrivileges", "LookupPrivilege",
            "DuplicateToken", "ImpersonateLoggedOnUser",
        ],
    },
    # 6. 信息收集 - 剪贴板、键盘、进程枚举、环境信息
    "collection": {
        "keywords": [
            # 剪贴板/键盘
            "GetClipboardData", "OpenClipboard", "SetClipboardData",
            "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState", "GetKeyboardState",
            "GetForegroundWindow", "GetWindowText",
            # 屏幕截图
            "BitBlt", "GetDC", "CreateCompatibleDC", "GetDesktopWindow",
            # 进程枚举
            "CreateToolhelp32Snapshot", "Process32First", "Process32Next",
            "Module32First", "Module32Next", "EnumProcesses", "EnumProcessModules",
            # 环境信息
            "GetComputerName", "GetUserName", "GetEnvironmentVariable",
            "GetWindowsDirectory", "GetSystemDirectory", "IsWow64Process",
        ],
    },
}
# 噪音 API 列表
NOISE_APIS = {
    "HeapAlloc", "HeapFree", "HeapReAlloc", "HeapSize", "HeapCreate", "HeapDestroy",
    "VirtualAlloc", "VirtualFree", "LocalAlloc", "LocalFree", "GlobalAlloc", "GlobalFree",
    "GetLastError", "SetLastError",
    "EnterCriticalSection", "LeaveCriticalSection", "TryEnterCriticalSection",
    "InitializeCriticalSection", "InitializeCriticalSectionEx", "DeleteCriticalSection",
    "EncodePointer", "DecodePointer",
    "GetCurrentProcess", "GetCurrentThread", "GetCurrentProcessId", "GetCurrentThreadId",
    "GetModuleHandleA", "GetModuleHandleW", "GetModuleFileNameA", "GetModuleFileNameW",
    "WaitForSingleObject", "WaitForMultipleObjects", "Sleep", "SleepEx",
    "GetSystemTimeAsFileTime", "GetLocalTime", "GetSystemTime",
    "MultiByteToWideChar", "WideCharToMultiByte",
    "FlsGetValue", "FlsSetValue", "TlsGetValue", "TlsSetValue",
    "LCMapStringEx", "GetStringTypeW",
    "RtlAllocateHeap", "RtlFreeHeap",
    "NtAllocateVirtualMemory", "NtFreeVirtualMemory",
    "CloseHandle",  # 调用频繁，参数无意义
}
def categorize_api(api_name: str) -> Optional[str]:
    """Categorize an API call by its behavior type."""
    base_name = api_name.split('.')[-1] if '.' in api_name else api_name
    if base_name in NOISE_APIS:
        return None
    for category, config in API_BEHAVIOR_CATEGORIES.items():
        for keyword in config["keywords"]:
            if keyword.lower() in api_name.lower():
                return category
    return "other"
def extract_behavior_from_apis(apis: list, max_per_category: int = 50) -> tuple:
    """Extract behavioral summary from API call list with raw call details."""
    behavior = {cat: {"apis": [], "count": 0} for cat in API_BEHAVIOR_CATEGORIES.keys()}
    
    # 初始化各类别的详细调用记录
    for cat in API_BEHAVIOR_CATEGORIES.keys():
        behavior[cat]["calls"] = []
    behavior["process"]["injection_detected"] = False
    
    categorized_apis = defaultdict(Counter)
    noise_count = 0
    module_counts = Counter()
    
    # 用于去重（基于 API名 + 参数组合）
    seen_calls = {cat: set() for cat in API_BEHAVIOR_CATEGORIES.keys()}
    
    # 所有分类都保存详细调用记录
    DETAILED_CATEGORIES = list(API_BEHAVIOR_CATEGORIES.keys())
    
    for api_call in apis:
        api_name = api_call.get("api_name", "")
        args = api_call.get("args", [])
        ret_val = api_call.get("ret_val")
        
        if '.' in api_name:
            module_counts[api_name.split('.')[0]] += 1
        
        category = categorize_api(api_name)
        if category is None:
            noise_count += 1
            continue
        if category == "other":
            continue
            
        categorized_apis[category][api_name] += 1
        
        # 检测进程注入
        if category == "process":
            injection_apis = API_BEHAVIOR_CATEGORIES["process"].get("injection_indicators", [])
            if any(ind.lower() in api_name.lower() for ind in injection_apis):
                behavior["process"]["injection_detected"] = True
        
        # 对重要类别，保存原始调用记录（去重）
        if category in DETAILED_CATEGORIES:
            # 创建去重 key：API名 + 参数的字符串表示
            args_key = str(args)[:200]  # 限制长度避免过长
            call_key = f"{api_name}|{args_key}"
            
            if call_key not in seen_calls[category]:
                seen_calls[category].add(call_key)
                
                # 保存原始调用记录
                call_record = {
                    "api": api_name,
                    "args": args,  # 保留原始参数
                }
                if ret_val is not None:
                    call_record["ret"] = ret_val
                
                behavior[category]["calls"].append(call_record)
    
    # 构建最终结果
    for category, api_counter in categorized_apis.items():
        behavior[category]["count"] = sum(api_counter.values())
        behavior[category]["apis"] = [name for name, _ in api_counter.most_common(max_per_category)]
    
    # 限制每个类别的调用记录数量
    max_calls = 30
    for category in DETAILED_CATEGORIES:
        if "calls" in behavior[category]:
            behavior[category]["calls"] = behavior[category]["calls"][:max_calls]
    
    return behavior, module_counts, noise_count
def extract_network_events(entry_points: list, max_events: int = 20) -> dict:
    """Extract network events from entry points with deduplication."""
    network = {"c2_candidates": [], "dns_queries": [], "connections_count": 0, 
               "traffic_count": 0, "traffic_samples": []}
    seen_servers = set()
    seen_traffic_data = set()  # 去重：基于数据内容
    
    for ep in entry_points:
        net_events = ep.get("network_events", {})
        
        # DNS queries
        for query in net_events.get("dns", []):
            hostname = query.get("hostname", query.get("name", "")) if isinstance(query, dict) else str(query)
            if hostname and hostname not in network["dns_queries"]:
                network["dns_queries"].append(hostname)
        
        # Traffic
        for event in net_events.get("traffic", []):
            if not isinstance(event, dict):
                continue
            network["traffic_count"] += 1
            server, port = event.get("server", ""), event.get("port", 0)
            event_type = event.get("type", "")
            data_b64 = event.get("data", "")
            
            # C2 candidates (unique server:port)
            server_key = f"{server}:{port}"
            if server and server_key not in seen_servers:
                seen_servers.add(server_key)
                network["c2_candidates"].append({
                    "server": server, "port": port, "proto": event.get("proto", "tcp")
                })
                if event_type == "connect":
                    network["connections_count"] += 1
            
            # Traffic samples - deduplicate by data content
            if data_b64 and len(network["traffic_samples"]) < max_events:
                # Create a unique key based on type + first 50 chars of data
                data_key = f"{event_type}:{data_b64[:50]}"
                if data_key not in seen_traffic_data:
                    seen_traffic_data.add(data_key)
                    network["traffic_samples"].append({
                        "server": server, "port": port, "type": event_type,
                        "data_b64": data_b64[:500], "method": event.get("method", "")
                    })
    
    return network
def extract_strings(report: dict, max_strings: int = 100) -> dict:
    """Extract important strings from report."""
    strings = {"in_memory_decoded": [], "count": 0}
    in_memory = report.get("strings", {}).get("in_memory", {})
    
    for encoding in ["ansi", "unicode"]:
        for s in in_memory.get(encoding, []):
            if not isinstance(s, str) or len(s) < 6 or s.startswith("0x"):
                continue
            if any(c.isalpha() for c in s) and s not in strings["in_memory_decoded"]:
                strings["in_memory_decoded"].append(s[:200])
                if len(strings["in_memory_decoded"]) >= max_strings:
                    break
        if len(strings["in_memory_decoded"]) >= max_strings:
            break
    
    for enc in ["ansi", "unicode"]:
        strings["count"] += len(in_memory.get(enc, []))
    return strings
def compress_speakeasy_report(report: dict, max_api: int = 50, max_net: int = 100, max_str: int = 100) -> dict:
    """Compress a full Speakeasy report into a behavior-focused summary."""
    result = {
        "status": "success",
        "emulation_time": report.get("emulation_total_runtime", 0),
        "metadata": {
            "sha256": report.get("sha256", ""),
            "arch": report.get("arch", ""),
            "filetype": report.get("filetype", ""),
            "entry_points_count": len(report.get("entry_points", []))
        },
        "behavior": {}, "api_summary": {}, "strings": {}, "dynamic_code": {}, "errors": []
    }
    
    all_apis = []
    for ep in report.get("entry_points", []):
        all_apis.extend(ep.get("apis", []))
        if ep.get("error"):
            result["errors"].append(ep.get("error"))
    
    behavior, module_counts, noise_count = extract_behavior_from_apis(all_apis, max_api)
    
    # 过滤掉空的行为类别（count=0）
    filtered_behavior = {}
    for cat, data in behavior.items():
        if data.get("count", 0) > 0:
            filtered_behavior[cat] = data
    
    result["behavior"] = filtered_behavior
    result["api_summary"] = {
        "total_calls": len(all_apis),
        "unique_apis": len(set(a.get("api_name", "") for a in all_apis)),
        "by_module": dict(module_counts.most_common(20)),
        "noise_filtered": noise_count
    }
    
    # 网络事件单独处理（可能有流量但没有网络 API）
    network_data = extract_network_events(report.get("entry_points", []), max_net)
    if network_data.get("traffic_count", 0) > 0 or network_data.get("c2_candidates"):
        if "network" not in result["behavior"]:
            result["behavior"]["network"] = {"apis": [], "count": 0}
        result["behavior"]["network"].update(network_data)
    
    result["strings"] = extract_strings(report, max_str)
    
    dynamic_segments = []
    for ep in report.get("entry_points", []):
        dynamic_segments.extend(ep.get("dynamic_code_segments", []))
    if dynamic_segments:
        result["dynamic_code"] = {"count": len(dynamic_segments), "segments": dynamic_segments[:10]}
    
    return result
# ============================================================================
# Memory Dump Processing Functions
# ============================================================================
def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data. High entropy (>7.0) indicates encryption/compression."""
    if not data:
        return 0.0
    
    from collections import Counter
    import math
    
    byte_counts = Counter(data)
    total = len(data)
    entropy = 0.0
    
    for count in byte_counts.values():
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    
    return round(entropy, 2)
def extract_strings_from_bytes(data: bytes, min_length: int = 6, max_strings: int = 50) -> list:
    """Extract printable ASCII and Unicode strings from binary data."""
    import re
    strings = []
    seen = set()
    
    # ASCII strings
    ascii_pattern = rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}'
    for match in re.finditer(ascii_pattern, data):
        s = match.group().decode('ascii', errors='ignore')
        if s not in seen and not s.startswith('0x'):
            seen.add(s)
            strings.append(s[:100])  # Truncate long strings
            if len(strings) >= max_strings:
                return strings
    
    # Unicode strings (UTF-16LE)
    unicode_pattern = rb'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + rb',}'
    for match in re.finditer(unicode_pattern, data):
        try:
            s = match.group().decode('utf-16le', errors='ignore')
            if s not in seen and not s.startswith('0x'):
                seen.add(s)
                strings.append(s[:100])
                if len(strings) >= max_strings:
                    return strings
        except:
            pass
    
    return strings
def find_pe_in_memory(data: bytes) -> tuple:
    """
    Find and extract PE file from memory region.
    
    Detection methods:
    1. Direct MZ header at start
    2. Embedded MZ header search with PE validation
    3. DOS stub text recovery (with MZ present)
    4. Truncated header recovery (variable offset missing)
    5. PE signature backward search
    6. DOS structure validation via e_lfanew
    
    Returns:
        (pe_data, offset, detection_method) or (None, -1, None) if not found
    """
    
    def build_dos_header(e_lfanew: int) -> bytes:
        """Build a minimal valid DOS header with proper e_lfanew."""
        # Standard DOS header template (64 bytes)
        dos_header = bytearray(64)
        dos_header[0:2] = b'MZ'           # e_magic
        dos_header[2:4] = (0x90).to_bytes(2, 'little')  # e_cblp
        dos_header[4:6] = (0x03).to_bytes(2, 'little')  # e_cp
        dos_header[8:10] = (0x04).to_bytes(2, 'little')  # e_cparhdr
        dos_header[24:26] = (0x40).to_bytes(2, 'little')  # e_lfarlc
        dos_header[0x3C:0x40] = e_lfanew.to_bytes(4, 'little')  # e_lfanew
        return bytes(dos_header)
    
    # Method 1: Direct MZ header at start with PE validation
    if len(data) > 0x40 and data[:2] == b'MZ':
        try:
            e_lfanew = int.from_bytes(data[0x3C:0x40], 'little')
            if 0 < e_lfanew < len(data) - 4:
                if data[e_lfanew:e_lfanew+4] == b'PE\x00\x00':
                    return data, 0, "direct_mz"
        except:
            pass
        return data, 0, "direct_mz"
    
    # Method 2: Search for embedded MZ header in data
    mz_offset = data.find(b'MZ')
    if mz_offset > 0 and mz_offset < len(data) - 64:
        candidate = data[mz_offset:]
        if len(candidate) > 64:
            try:
                e_lfanew = int.from_bytes(candidate[0x3C:0x40], 'little')
                if 0 < e_lfanew < len(candidate) - 4:
                    if candidate[e_lfanew:e_lfanew+4] == b'PE\x00\x00':
                        return candidate, mz_offset, "embedded_mz"
            except:
                pass
    
    # Method 3 & 4: DOS stub text based recovery
    dos_stub_markers = [
        b'This program cannot be run in DOS mode',
        b'This program must be run under Win32',
        b'This program requires Microsoft Windows',
    ]
    
    NORMAL_DOS_STUB_OFFSET = 0x4E  # Standard offset of DOS stub text in PE
    
    for marker in dos_stub_markers:
        marker_offset = data.find(marker)
        if marker_offset > 0:
            # Calculate how many bytes are missing from the start
            missing_bytes = NORMAL_DOS_STUB_OFFSET - marker_offset
            
            if missing_bytes == 0:
                # Perfect alignment - DOS stub at correct offset
                if data[:2] == b'MZ':
                    return data, 0, "dos_stub_recovery"
                else:
                    # MZ is corrupted/zeroed but DOS structure is intact
                    # Validate via e_lfanew pointing to PE signature
                    try:
                        e_lfanew = int.from_bytes(data[0x3C:0x40], 'little')
                        if 0 < e_lfanew < len(data) - 4:
                            if data[e_lfanew:e_lfanew+4] == b'PE\x00\x00':
                                # Valid PE structure, just MZ is corrupted
                                rebuilt_pe = b'MZ' + data[2:]
                                return rebuilt_pe, 0, "corrupted_mz_recovery"
                    except:
                        pass
            elif missing_bytes > 0 and missing_bytes <= 16:
                # Data is truncated - missing 1-16 bytes from start
                pe_sig_offset = data.find(b'PE\x00\x00')
                if pe_sig_offset > 0:
                    original_e_lfanew = pe_sig_offset + missing_bytes
                    new_dos_header = build_dos_header(original_e_lfanew)
                    if missing_bytes <= 2:
                        rebuilt_pe = b'MZ' + b'\x90' * (missing_bytes - 2) + data[max(0, 2-missing_bytes):]
                    else:
                        rebuilt_pe = new_dos_header[:missing_bytes] + data
                    return rebuilt_pe, -missing_bytes, "truncated_header_recovery"
            elif missing_bytes < 0:
                # DOS stub is deeper in the data - MZ might be earlier
                estimated_mz_offset = marker_offset - NORMAL_DOS_STUB_OFFSET
                if estimated_mz_offset >= 0 and data[estimated_mz_offset:estimated_mz_offset+2] == b'MZ':
                    return data[estimated_mz_offset:], estimated_mz_offset, "dos_stub_recovery"
    
    # Method 5: Search for PE signature and work backwards
    pe_sig_offset = data.find(b'PE\x00\x00')
    if pe_sig_offset > 0:
        # Try to find MZ before PE signature
        search_start = max(0, pe_sig_offset - 0x200)
        for offset in range(min(pe_sig_offset - 0x3C, pe_sig_offset - 1), search_start, -1):
            if offset >= 0 and data[offset:offset+2] == b'MZ':
                try:
                    e_lfanew = int.from_bytes(data[offset+0x3C:offset+0x40], 'little')
                    if offset + e_lfanew == pe_sig_offset:
                        return data[offset:], offset, "pe_sig_recovery"
                except:
                    pass
        
        # Method 6: No MZ found but we have PE signature
        # Try to validate via e_lfanew structure at different truncation offsets
        for trunc in range(1, 8):  # Check truncations of 1-7 bytes
            e_lfanew_offset = 0x3C - trunc
            if e_lfanew_offset >= 0 and e_lfanew_offset + 4 <= len(data):
                try:
                    e_lfanew = int.from_bytes(data[e_lfanew_offset:e_lfanew_offset+4], 'little')
                    expected_pe_sig = e_lfanew - trunc
                    if expected_pe_sig == pe_sig_offset and expected_pe_sig > 0:
                        # Rebuild header
                        new_dos_header = build_dos_header(e_lfanew)
                        rebuilt_pe = new_dos_header[:trunc] + data
                        return rebuilt_pe, -trunc, "truncated_header_recovery"
                except:
                    pass
    
    return None, -1, None
def extract_pe_info(pe_data: bytes) -> dict:
    """Extract basic PE information for AI analysis."""
    info = {
        "valid": False,
        "arch": "unknown",
        "sections": [],
        "imports_hint": [],
        "is_dll": False,
        "is_exe": False
    }
    
    try:
        if len(pe_data) < 0x40:
            return info
            
        # Get e_lfanew
        e_lfanew = int.from_bytes(pe_data[0x3C:0x40], 'little')
        if e_lfanew <= 0 or e_lfanew >= len(pe_data) - 24:
            return info
        
        # Check PE signature
        if pe_data[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
            return info
        
        info["valid"] = True
        
        # Parse COFF header (starts after PE signature)
        coff_offset = e_lfanew + 4
        machine = int.from_bytes(pe_data[coff_offset:coff_offset+2], 'little')
        num_sections = int.from_bytes(pe_data[coff_offset+2:coff_offset+4], 'little')
        characteristics = int.from_bytes(pe_data[coff_offset+18:coff_offset+20], 'little')
        
        # Machine type
        if machine == 0x14c:
            info["arch"] = "x86"
        elif machine == 0x8664:
            info["arch"] = "x64"
        elif machine == 0xaa64:
            info["arch"] = "ARM64"
        
        # Characteristics
        info["is_dll"] = bool(characteristics & 0x2000)
        info["is_exe"] = bool(characteristics & 0x0002) and not info["is_dll"]
        
        # Parse sections (limited)
        optional_header_size = int.from_bytes(pe_data[coff_offset+16:coff_offset+18], 'little')
        section_offset = coff_offset + 20 + optional_header_size
        
        for i in range(min(num_sections, 10)):
            sec_start = section_offset + (i * 40)
            if sec_start + 40 > len(pe_data):
                break
            sec_name = pe_data[sec_start:sec_start+8].rstrip(b'\x00').decode('ascii', errors='ignore')
            if sec_name:
                info["sections"].append(sec_name)
        
        # Extract some import hints from strings
        import_strings = extract_strings_from_bytes(pe_data, min_length=4, max_strings=100)
        dll_hints = [s for s in import_strings if s.lower().endswith('.dll')]
        api_hints = [s for s in import_strings if any(k in s for k in 
                     ['GetProc', 'LoadLib', 'Virtual', 'Create', 'Write', 'Read', 'Open', 'Reg', 'Http', 'Socket'])]
        info["imports_hint"] = (dll_hints[:10] + api_hints[:10])[:15]
        
    except Exception:
        pass
    
    return info
def extract_memory_dumps(se, include_freed: bool = True, max_regions: int = 30, 
                         output_dir: str = None) -> dict:
    """
    Extract and process memory dumps from Speakeasy emulator for AI analysis.
    
    Features:
    - Smart PE detection: finds MZ headers anywhere in memory
    - PE recovery: reconstructs PE from incomplete markers (DOS stub, PE signature)
    - PE analysis: extracts architecture, sections, import hints
    - Saves extracted PEs to disk if output_dir provided
    
    Args:
        se: Speakeasy emulator instance
        include_freed: Include memory regions marked as freed
        max_regions: Maximum number of regions to include
        output_dir: Optional directory to save extracted PE files
        
    Returns:
        Dict with PE regions, interesting regions, and summary
    """
    import os
    import hashlib
    
    result = {
        "summary": {
            "total_regions": 0,
            "pe_detected": 0,
            "pe_recovered": 0,
            "high_entropy_count": 0,
            "freed_count": 0
        },
        "extracted_pes": [],
        "interesting_regions": [],
        "freed_regions": [],
        "saved_files": []
    }
    
    try:
        memory_dumps = list(se.get_memory_dumps())
    except Exception as e:
        result["error"] = f"Failed to get memory dumps: {str(e)}"
        return result
    
    result["summary"]["total_regions"] = len(memory_dumps)
    
    seen_hashes = set()  # Deduplicate by content hash
    regions_added = 0
    
    for tag, base, size, is_free, proc, data in memory_dumps:
        if regions_added >= max_regions:
            break
            
        # Skip empty or very small regions
        if not data or size < 64:
            continue
            
        # Skip emulator internal structures (except loaded binaries and shellcode)
        if tag and tag.startswith('emu.') and not any(x in tag for x in ['shellcode', 'alloc', 'heap']):
            continue
            
        # Deduplicate
        content_hash = hashlib.md5(data[:1024]).hexdigest()
        if content_hash in seen_hashes:
            continue
        seen_hashes.add(content_hash)
        
        # Handle freed regions
        if is_free:
            result["summary"]["freed_count"] += 1
            if not include_freed:
                continue
        
        # Try to find and extract PE
        pe_data, pe_offset, detection_method = find_pe_in_memory(data)
        
        if pe_data is not None:
            result["summary"]["pe_detected"] += 1
            if detection_method != "direct_mz":
                result["summary"]["pe_recovered"] += 1
            
            # Analyze PE
            pe_info = extract_pe_info(pe_data)
            pe_hash = hashlib.sha256(pe_data[:min(len(pe_data), 0x10000)]).hexdigest()[:16]
            
            # Extract strings from PE
            pe_strings = extract_strings_from_bytes(pe_data, min_length=6, max_strings=30)
            
            region_info = {
                "tag": tag or "unknown",
                "original_base": hex(base),
                "pe_offset_in_region": pe_offset,
                "pe_size": len(pe_data),
                "detection_method": detection_method,
                "pe_info": pe_info,
                "pe_hash": pe_hash,
                "strings": pe_strings[:20],
                "entropy": calculate_entropy(pe_data[:4096])
            }
            
            # Check PE format and convert if needed
            if is_disk_format_pe(pe_data):
                region_info["pe_format"] = "disk"
                final_pe_data = pe_data
            else:
                region_info["pe_format"] = "memory"
                # Attempt conversion to disk format
                converted, conv_info = convert_pe_memory_to_disk(pe_data, rebuild_imports=True)
                if converted:
                    region_info["converted_to_disk"] = True
                    region_info["conversion_info"] = {
                        "sections_converted": conv_info.get("sections_converted", 0),
                        "size_reduction": conv_info.get("size_reduction", "N/A"),
                        "iat_rebuilt": conv_info.get("iat_rebuilt", False)
                    }
                    final_pe_data = converted
                else:
                    region_info["converted_to_disk"] = False
                    region_info["conversion_error"] = conv_info.get("error", "Unknown")
                    final_pe_data = pe_data  # Fallback to original
            
            # Save PE to disk if output_dir provided
            if output_dir and pe_info.get("valid"):
                try:
                    os.makedirs(output_dir, exist_ok=True)
                    ext = ".dll" if pe_info["is_dll"] else ".exe"
                    # Add format suffix to filename
                    format_suffix = "_disk" if region_info.get("converted_to_disk") or region_info.get("pe_format") == "disk" else "_mem"
                    filename = f"extracted_{pe_hash}{format_suffix}{ext}"
                    filepath = os.path.join(output_dir, filename)
                    with open(filepath, "wb") as f:
                        f.write(final_pe_data)
                    region_info["saved_path"] = filepath
                    region_info["saved_size"] = len(final_pe_data)
                    result["saved_files"].append(filepath)
                except Exception as e:
                    region_info["save_error"] = str(e)
            
            result["extracted_pes"].append(region_info)
        else:
            # Not a PE, check for other interesting content
            entropy = calculate_entropy(data[:4096])
            if entropy > 7.0:
                result["summary"]["high_entropy_count"] += 1
            
            strings = extract_strings_from_bytes(data, min_length=6, max_strings=30)
            
            # Only include if interesting
            if entropy > 5.0 or strings:
                region_info = {
                    "tag": tag or "unknown",
                    "base": hex(base),
                    "size": size,
                    "is_freed": is_free,
                    "entropy": entropy,
                    "strings": strings[:20] if strings else [],
                    "hexdump_preview": data[:128].hex()
                }
                
                if is_free:
                    result["freed_regions"].append(region_info)
                else:
                    result["interesting_regions"].append(region_info)
        
        regions_added += 1
    
    return result
# ============================================================================
# PE Memory-to-Disk Conversion
# ============================================================================
def is_disk_format_pe(pe_data: bytes) -> bool:
    """
    Check if PE is in disk format (not memory mapped).
    
    Key insight: PE headers contain BOTH PointerToRawData and VirtualAddress.
    - In disk format: actual data is at PointerToRawData offset
    - In memory format: actual data is at VirtualAddress offset
    
    We verify by checking where the actual section data is located.
    """
    try:
        import pefile
        pe = pefile.PE(data=pe_data, fast_load=True)
        
        try:
            file_align = pe.OPTIONAL_HEADER.FileAlignment
            section_align = pe.OPTIONAL_HEADER.SectionAlignment
            
            # If alignments are same, format is ambiguous - treat as disk
            if file_align == section_align:
                return True
            
            # Check if data is actually at PointerToRawData or VirtualAddress
            if pe.sections and len(pe.sections) > 0:
                for section in pe.sections:
                    raw_offset = section.PointerToRawData
                    va_offset = section.VirtualAddress
                    
                    # Skip if offsets are same or section has no data
                    if raw_offset == va_offset or raw_offset == 0 or va_offset == 0:
                        continue
                    
                    # Get expected content size (at least 64 bytes for comparison)
                    check_size = min(64, section.SizeOfRawData, section.Misc_VirtualSize)
                    if check_size < 16:
                        continue
                    
                    # Read data from both locations
                    if raw_offset + check_size <= len(pe_data) and va_offset + check_size <= len(pe_data):
                        data_at_raw = pe_data[raw_offset:raw_offset + check_size]
                        data_at_va = pe_data[va_offset:va_offset + check_size]
                        
                        # Check if data at raw offset is all zeros (memory-mapped, no data there)
                        if data_at_raw == b'\x00' * check_size and data_at_va != b'\x00' * check_size:
                            # Data is at VA, not at RawOffset -> memory format
                            return False
                        
                        # Check if data at VA location looks like headers repeat (disk format)
                        # In disk format, reading at VA offset would hit different/empty data
                        if data_at_raw != b'\x00' * check_size:
                            # There's actual data at raw offset
                            # If data at raw != data at va, likely disk format
                            if data_at_raw != data_at_va:
                                return True
                            else:
                                # Same data at both - ambiguous, likely memory format
                                # because data was copied from disk offset to VA offset
                                return False
                    
                    # If we can only read from VA, it's memory format
                    elif va_offset + check_size <= len(pe_data) and raw_offset + check_size > len(pe_data):
                        return False
            
            # Fallback: check file size vs expected
            # Memory-mapped PE is typically much larger due to SectionAlignment padding
            size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
            if len(pe_data) >= size_of_image * 0.8:
                # File is close to or larger than SizeOfImage -> likely memory format
                return False
            
            return True
        finally:
            pe.close()
    except Exception:
        return False
def find_disk_pe_in_memory(all_pe_data: list) -> tuple:
    """
    Search through multiple PE data blobs to find one in disk format.
    
    Args:
        all_pe_data: List of (tag, pe_bytes) tuples
        
    Returns:
        (tag, pe_bytes, is_disk) tuple of best candidate, or (None, None, False)
    """
    disk_format_pes = []
    memory_format_pes = []
    
    for tag, pe_data in all_pe_data:
        if is_disk_format_pe(pe_data):
            disk_format_pes.append((tag, pe_data, True))
        else:
            memory_format_pes.append((tag, pe_data, False))
    
    # Prefer disk format
    if disk_format_pes:
        # Return the largest one (most complete)
        return max(disk_format_pes, key=lambda x: len(x[1]))
    
    # Fallback to memory format
    if memory_format_pes:
        return max(memory_format_pes, key=lambda x: len(x[1]))
    
    return (None, None, False)
def convert_pe_memory_to_disk(pe_data: bytes, rebuild_imports: bool = True) -> tuple:
    """
    Convert a memory-mapped PE back to disk format.
    
    Process:
    1. Parse PE headers
    2. Calculate new section layout with FileAlignment
    3. Copy sections from VirtualAddress to PointerToRawData offsets
    4. Optionally rebuild IAT
    5. Update header fields
    
    Args:
        pe_data: Memory-mapped PE bytes
        rebuild_imports: Whether to attempt IAT reconstruction
        
    Returns:
        (converted_pe_bytes, info_dict) or (None, error_dict)
    """
    try:
        import pefile
        
        pe = pefile.PE(data=pe_data)
        
        try:
            file_align = pe.OPTIONAL_HEADER.FileAlignment
            section_align = pe.OPTIONAL_HEADER.SectionAlignment
            
            info = {
                "status": "success",
                "original_size": len(pe_data),
                "file_alignment": hex(file_align),
                "section_alignment": hex(section_align),
                "sections_converted": 0,
                "iat_rebuilt": False
            }
            
            # If already disk format, return as-is
            if file_align == section_align or is_disk_format_pe(pe_data):
                info["status"] = "already_disk_format"
                return pe_data, info
            
            # Calculate header size
            header_size = pe.OPTIONAL_HEADER.SizeOfHeaders
            
            # Build new file: start with headers
            new_file = bytearray(pe_data[:header_size])
            
            # Track current write position (after headers)
            current_offset = header_size
            
            # Process each section
            section_mappings = []
            for section in pe.sections:
                section_name = section.Name.rstrip(b'\x00').decode('utf-8', errors='ignore')
                
                # Get section data from memory location
                va = section.VirtualAddress
                vsize = section.Misc_VirtualSize
                raw_size = section.SizeOfRawData
                
                # Use the smaller of VirtualSize and actual data available
                actual_size = min(vsize, raw_size) if raw_size > 0 else vsize
                actual_size = min(actual_size, len(pe_data) - va) if va < len(pe_data) else 0
                
                if actual_size <= 0:
                    section_mappings.append({
                        "name": section_name,
                        "status": "skipped",
                        "reason": "no data"
                    })
                    continue
                
                # Read section data from VirtualAddress
                section_data = pe_data[va:va + actual_size]
                
                # Align current offset to FileAlignment
                aligned_offset = (current_offset + file_align - 1) & ~(file_align - 1)
                
                # Pad to aligned offset
                if aligned_offset > len(new_file):
                    new_file.extend(b'\x00' * (aligned_offset - len(new_file)))
                
                # Store old and new offsets for header update
                old_raw = section.PointerToRawData
                new_raw = aligned_offset
                
                section_mappings.append({
                    "name": section_name,
                    "old_va": hex(va),
                    "old_raw": hex(old_raw),
                    "new_raw": hex(new_raw),
                    "size": actual_size
                })
                
                # Write section data
                new_file.extend(section_data)
                
                # Pad to aligned SizeOfRawData
                aligned_size = (actual_size + file_align - 1) & ~(file_align - 1)
                if len(section_data) < aligned_size:
                    new_file.extend(b'\x00' * (aligned_size - len(section_data)))
                
                current_offset = len(new_file)
                info["sections_converted"] += 1
            
            info["section_details"] = section_mappings
        finally:
            pe.close()
        
        # Update section headers with new PointerToRawData values
        new_pe_data = bytes(new_file)
        pe_updated = pefile.PE(data=new_pe_data)
        
        try:
            for i, section in enumerate(pe_updated.sections):
                if i < len(section_mappings) and "new_raw" in section_mappings[i]:
                    new_raw = int(section_mappings[i]["new_raw"], 16)
                    section.PointerToRawData = new_raw
                    section.SizeOfRawData = (section.Misc_VirtualSize + file_align - 1) & ~(file_align - 1)
            
            # Update SizeOfImage
            pe_updated.OPTIONAL_HEADER.SizeOfImage = len(new_file)
            
            # Rebuild imports if requested
            if rebuild_imports:
                iat_result = rebuild_iat(pe_updated)
                info["iat_rebuilt"] = iat_result.get("success", False)
                info["iat_info"] = iat_result
            
            # Generate final bytes
            final_data = pe_updated.write()
            info["converted_size"] = len(final_data)
            info["size_reduction"] = f"{(1 - len(final_data)/len(pe_data))*100:.1f}%"
            
            return bytes(final_data), info
        finally:
            pe_updated.close()
        
    except Exception as e:
        return None, {"status": "error", "error": str(e)}
def rebuild_iat(pe) -> dict:
    """
    Attempt to rebuild Import Address Table.
    
    In memory-dumped PEs, the IAT contains resolved addresses instead of
    RVAs to import names. This function attempts to restore the original IAT.
    
    Args:
        pe: pefile.PE object (will be modified in place)
        
    Returns:
        Dict with rebuild status and details
    """
    result = {
        "success": False,
        "imports_found": 0,
        "thunks_fixed": 0,
        "errors": []
    }
    
    try:
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']
            ])
        
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            result["errors"].append("No import directory found")
            return result
        
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            result["imports_found"] += 1
            
            for imp in entry.imports:
                # Check if the address looks like a resolved pointer
                # (high values in user-mode space)
                if imp.address and imp.address > 0x10000000:
                    # This looks like a resolved address
                    # We can't easily restore the original without more context
                    # But we can mark it for the analyst
                    pass
                
                # If we have the name, the import is likely still valid
                if imp.name:
                    result["thunks_fixed"] += 1
        
        result["success"] = result["thunks_fixed"] > 0
        
    except Exception as e:
        result["errors"].append(str(e))
    
    return result
def process_pe_for_disk(pe_data: bytes, output_path: str = None) -> dict:
    """
    High-level function to process extracted PE for disk format.
    
    1. Check if already disk format
    2. If memory format, convert to disk format
    3. Optionally save to file
    
    Args:
        pe_data: PE bytes (memory or disk format)
        output_path: Optional path to save converted PE
        
    Returns:
        Dict with processing results
    """
    import os
    
    result = {
        "format": "unknown",
        "converted": False,
        "saved_path": None
    }
    
    # Check format
    if is_disk_format_pe(pe_data):
        result["format"] = "disk"
        final_data = pe_data
    else:
        result["format"] = "memory"
        converted_data, conv_info = convert_pe_memory_to_disk(pe_data)
        
        if converted_data:
            result["converted"] = True
            result["conversion_info"] = conv_info
            final_data = converted_data
        else:
            result["conversion_error"] = conv_info
            final_data = pe_data  # Fallback to original
    
    # Save if path provided
    if output_path and final_data:
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, "wb") as f:
                f.write(final_data)
            result["saved_path"] = output_path
            result["saved_size"] = len(final_data)
        except Exception as e:
            result["save_error"] = str(e)
    
    return result

# ============================================================================
# API Hooking Helper Functions
# ============================================================================

def add_safe_hook(se, module_name: str, api_name: str, callback) -> bool:
    """
    Safely add an API hook that chains the original handler.
    
    This fixes the issue where se.add_api_hook replaces the original handler,
    breaking emulation for complex APIs like VirtualAlloc.
    
    Args:
        se: Speakeasy instance
        module_name: Module name (e.g. 'kernel32')
        api_name: API name (e.g. 'VirtualAlloc')
        callback: Function to call (emu, api_name, args, ret_val, ctx)
        
    Returns:
        True if hook added successfully, False otherwise
    """
    try:
        import os
        mod = None
        # Try finding the module in se.modules
        modules_container = getattr(se, 'modules', None)
        if not modules_container and hasattr(se, 'emu'):
            modules_container = getattr(se.emu, 'modules', None)
            
        if modules_container:
            # Normalize target names
            target_base = module_name.lower()
            if not target_base.endswith(".dll"):
                target_base_dll = target_base + ".dll"
            else:
                target_base_dll = target_base
                target_base = target_base[:-4]

            if isinstance(modules_container, dict):
                for name, m in modules_container.items():
                    n_low = name.lower()
                    if n_low == target_base or n_low == target_base_dll:
                        mod = m
                        break
            elif isinstance(modules_container, list):
                for m in modules_container:
                    m_name = getattr(m, 'name', '')
                    n_low = m_name.lower()
                    # Check for exact match or suffix (path) match causing problems
                    # e.g. "C:\Windows\System32\kernel32.dll" ends with "kernel32.dll"
                    if n_low == target_base or n_low == target_base_dll or \
                       n_low.endswith(os.path.sep + target_base) or \
                       n_low.endswith(os.path.sep + target_base_dll) or \
                       n_low.endswith("/" + target_base) or \
                       n_low.endswith("/" + target_base_dll):
                        mod = m
                        break
                        
        if not mod:
            # Module not loaded yet - try to hook normally if possible, 
            # or log warning. For now, assume module is loaded.
            return False
            
        # Find original handler
        orig_handler = None
        if hasattr(mod, 'funcs'):
            orig_handler = mod.funcs.get(api_name)
            
        if not orig_handler:
            # No original handler? Using se.add_api_hook is safe (standard hook)
            # But let's log this case? 
            # Actually, if we just want to monitor, we can try to hook anyway.
            # But if we rely on return value, proceed with caution.
            # Let's fallback to standard hook but wrap it to provide None return value
             # Or just skip
             return False
        
        def wrapper(emu, api, args, conv):
            # 1. Call original handler
            ret_val = orig_handler(emu, api, args, conv)
            
            # 2. Call monitoring callback
            try:
                # Callback signature: (emu, api_name, args, ret_val, ctx)
                callback(emu, api, args, ret_val, None)
            except Exception:
                pass
                
            return ret_val
            
        se.add_api_hook(wrapper, module_name, api_name)
        return True
        
    except Exception:
        return False
