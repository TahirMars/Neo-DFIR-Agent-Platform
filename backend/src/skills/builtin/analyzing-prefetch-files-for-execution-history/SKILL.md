---
id: analyzing-prefetch-files-for-execution-history
name: analyzing-prefetch-files-for-execution-history
name_zh: 分析·Prefetch·文件·执行·历史
description: 解析 Windows 预取文件以确定程序执行历史记录，包括运行次数、时间戳和用于取证调查的引用文件。
domain: cybersecurity
subdomain: digital-forensics
tags:
- forensics
- prefetch
- windows-artifacts
- execution-history
- timeline-analysis
- evidence-collection
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 分析·Prefetch·文件·执行·历史

## 使用时机
- 确定 Windows 系统上执行了哪些程序以及何时执行
- 在恶意软件调查期间确认可疑二进制文件的执行
- 用于建立事件期间应用程序使用的时间表
- 将程序执行与其他取证工件关联时
- 识别反取证工具或运行的未经授权的软件

## 前置条件
- 从取证图像访问 Windows Prefetch 目录 (C:\Windows\Prefetch\)
- PECmd (Eric Zimmerman)、WinPrefetchView 或 python-prefetch 解析器
- 了解预取文件格式（版本 17、23、26、30）
- 启用预取的 Windows 系统（客户端操作系统上默认，服务器上禁用）
- 了解预取命名约定 (APPNAME-HASH.pf)

## 工作流程
### 第 1 步：从取证图像中提取预取文件

```bash
# Mount the forensic image
mount -o ro,loop,offset=$((2048*512)) /cases/case-2024-001/images/evidence.dd /mnt/evidence

# Copy all prefetch files
mkdir -p /cases/case-2024-001/prefetch/
cp /mnt/evidence/Windows/Prefetch/*.pf /cases/case-2024-001/prefetch/

# Count and list prefetch files
ls -la /cases/case-2024-001/prefetch/ | wc -l
ls -la /cases/case-2024-001/prefetch/ | head -30

# Hash all prefetch files for integrity
sha256sum /cases/case-2024-001/prefetch/*.pf > /cases/case-2024-001/prefetch/pf_hashes.txt

# Note: Prefetch filename format is EXECUTABLE_NAME-XXXXXXXX.pf
# The hash (XXXXXXXX) is based on the executable path
# Same executable from different paths creates different prefetch files
```

### 第 2 步：使用 PECmd 解析预取文件

```bash
# Using Eric Zimmerman's PECmd (Windows or via Mono/Wine on Linux)
# Download from https://ericzimmerman.github.io/

# Parse a single prefetch file
PECmd.exe -f "C:\cases\prefetch\POWERSHELL.EXE-A]B2C3D4.pf"

# Parse all prefetch files and output to CSV
PECmd.exe -d "C:\cases\prefetch\" --csv "C:\cases\analysis\" --csvf prefetch_results.csv

# Parse with JSON output
PECmd.exe -d "C:\cases\prefetch\" --json "C:\cases\analysis\" --jsonf prefetch_results.json

# Output includes for each file:
# - Executable name and path
# - Run count
# - Last run time (up to 8 timestamps in Windows 10)
# - Files and directories referenced during execution
# - Volume information (serial number, creation date)
# - Prefetch file creation time
```

### 第 3 步：使用 Python 进行基于 Linux 的分析

```bash
pip install prefetch

python3 << 'PYEOF'
import os
import json
from datetime import datetime

# Parse prefetch files using python
import struct

def parse_prefetch(filepath):
    """Parse a Windows Prefetch file."""
    with open(filepath, 'rb') as f:
        data = f.read()

    # Check for MAM compressed format (Windows 10)
    if data[:4] == b'MAM\x04':
        import lznt1  # or use DecompressBuffer
        # Windows 10 prefetch files are compressed
        print(f"  [Compressed Win10 format - use PECmd for full parsing]")
        return None

    # Version 17 (XP), 23 (Vista/7), 26 (8.1), 30 (10)
    version = struct.unpack('<I', data[0:4])[0]
    signature = data[4:8]

    if signature != b'SCCA':
        print(f"  Invalid prefetch signature")
        return None

    file_size = struct.unpack('<I', data[8:12])[0]
    exec_name = data[16:76].decode('utf-16-le').strip('\x00')
    run_count = struct.unpack('<I', data[208:212])[0] if version >= 23 else struct.unpack('<I', data[144:148])[0]

    result = {
        'version': version,
        'executable': exec_name,
        'file_size': file_size,
        'run_count': run_count,
    }

    # Extract last execution timestamps
    if version == 23:  # Vista/7 - 1 timestamp
        ts = struct.unpack('<Q', data[128:136])[0]
        result['last_run'] = filetime_to_datetime(ts)
    elif version >= 26:  # Win8+ - up to 8 timestamps
        timestamps = []
        for i in range(8):
            ts = struct.unpack('<Q', data[128+i*8:136+i*8])[0]
            if ts > 0:
                timestamps.append(filetime_to_datetime(ts))
        result['last_run_times'] = timestamps

    return result

def filetime_to_datetime(ft):
    """Convert Windows FILETIME to datetime string."""
    if ft == 0:
        return None
    timestamp = (ft - 116444736000000000) / 10000000
    try:
        return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S UTC')
    except (OSError, ValueError):
        return None

# Process all prefetch files
prefetch_dir = '/cases/case-2024-001/prefetch/'
results = []

for filename in sorted(os.listdir(prefetch_dir)):
    if filename.lower().endswith('.pf'):
        filepath = os.path.join(prefetch_dir, filename)
        print(f"\n=== {filename} ===")
        result = parse_prefetch(filepath)
        if result:
            print(f"  Executable: {result['executable']}")
            print(f"  Run Count:  {result['run_count']}")
            if 'last_run' in result:
                print(f"  Last Run:   {result['last_run']}")
            elif 'last_run_times' in result:
                for i, ts in enumerate(result['last_run_times']):
                    print(f"  Run Time {i+1}: {ts}")
            results.append(result)

# Save results
with open('/cases/case-2024-001/analysis/prefetch_analysis.json', 'w') as f:
    json.dump(results, f, indent=2)
PYEOF
```

### 第4步：识别可疑的执行证据

```bash
# Search for known malicious tool names in prefetch
ls /cases/case-2024-001/prefetch/ | grep -iE \
   '(MIMIKATZ|PSEXEC|WMIC|COBALT|BEACON|PWDUMP|PROCDUMP|LAZAGNE|RUBEUS|BLOODHOUND|SHARPHOUND|CERTUTIL|BITSADMIN)'

# Search for script interpreters (potential malicious execution)
ls /cases/case-2024-001/prefetch/ | grep -iE \
   '(POWERSHELL|CMD\.EXE|WSCRIPT|CSCRIPT|MSHTA|REGSVR32|RUNDLL32|MSIEXEC)'

# Search for remote access tools
ls /cases/case-2024-001/prefetch/ | grep -iE \
   '(TEAMVIEWER|ANYDESK|LOGMEIN|VNC|SPLASHTOP|SCREENCONNECT|AMMYY)'

# Search for data exfiltration tools
ls /cases/case-2024-001/prefetch/ | grep -iE \
   '(RAR|7Z|ZIP|RCLONE|MEGA|DROPBOX|ONEDRIVE|GDRIVE|FTP|CURL|WGET)'

# Find recently created prefetch files (newest executables run)
ls -lt /cases/case-2024-001/prefetch/ | head -20

# Cross-reference with Shimcache and Amcache for confirmation
# Prefetch existence = program was executed at least once
```

### 第 5 步：构建执行时间线

```bash
# Create timeline from prefetch data
python3 << 'PYEOF'
import json
import csv

with open('/cases/case-2024-001/analysis/prefetch_analysis.json') as f:
    data = json.load(f)

timeline = []
for entry in data:
    if 'last_run_times' in entry:
        for ts in entry['last_run_times']:
            if ts:
                timeline.append({
                    'timestamp': ts,
                    'executable': entry['executable'],
                    'run_count': entry['run_count'],
                    'source': 'Prefetch'
                })
    elif 'last_run' in entry and entry['last_run']:
        timeline.append({
            'timestamp': entry['last_run'],
            'executable': entry['executable'],
            'run_count': entry['run_count'],
            'source': 'Prefetch'
        })

# Sort chronologically
timeline.sort(key=lambda x: x['timestamp'])

# Write timeline CSV
with open('/cases/case-2024-001/analysis/execution_timeline.csv', 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['timestamp', 'executable', 'run_count', 'source'])
    writer.writeheader()
    writer.writerows(timeline)

# Print suspicious time window
for entry in timeline:
    if '2024-01-15' in entry['timestamp'] or '2024-01-16' in entry['timestamp']:
        print(f"  {entry['timestamp']} | {entry['executable']} (x{entry['run_count']})")
PYEOF
```

## 关键概念

| 概念 | 描述 |
|---------|-------------|
| 预取 | 预加载应用程序数据并跟踪执行的 Windows 性能优化 |
| SCCA签名 | 标识有效预取文件的魔术字节 |
| 路径哈希 | 构成 .pf 文件名一部分的可执行路径的基于 CRC 的哈希值 |
| 运行次数 | 可执行文件已启动的次数（可能会回绕）|
| 上次运行时间戳 | Windows 8+ 存储最多 8 个最近的执行时间戳 |
| 参考文件 | 执行前 10 秒期间访问的文件和目录列表 |
| 成本量信息 | 标识源卷的驱动器序列号和创建日期 |
| MAM 压缩 | Windows 10 Prefetch 文件使用 MAM4 压缩，需要在解析之前解压 |

## 工具和系统

| 工具 | 目的 |
|------|---------|
| PECmd | Eric Zimmerman 的带有 CSV/JSON 输出的 Prefetch 解析器 |
| WinPrefetchView | 用于查看 Prefetch 文件的 NirSoft GUI 工具 |
| python-prefetch | 用于解析 Prefetch 文件的 Python 库 |
| Prefetch 哈希计算器 | 从可执行路径计算预期哈希值的工具 |
| CAPE | 自动化工件收集，包括预取 |
| Autopsy | 具有 Prefetch 分析模块的取证平台 |
| Plaso/log2timeline | 包含 Prefetch 解析器的超级时间线工具 |
| Velociraptor | 具有预取收集和分析工件的端点代理 |

## 常见场景

**场景 1：确认恶意软件执行**
在 Prefetch 目录中搜索恶意软件可执行文件名称，通过 Prefetch 确认执行是否存在，提取运行计数和上次运行时间，识别引用的 DLL 以了解恶意软件行为，与注册表自动运行条目关联。

**场景 2：攻击者工具使用时间线**
识别 PsExec、Mimikatz、BloodHound 和其他攻击工具的预取文件，构建工具执行的时间顺序时间表，确定攻击顺序（侦察、凭证盗窃、横向移动），将时间戳与网络连接日志进行匹配。

**场景 3：数据暂存和渗透**
查找压缩工具（7z、WinRAR、zip）的预取条目，识别文件传输实用程序（rclone、FTP 客户端）的执行情况，检查云存储客户端执行情况、数据暂存和传输发生的时间线。

**场景4：反取证检测**
检查已知反取证工具（CCleaner、Eraser、SDelete）的执行情况，确定 Prefetch 目录最近是否被清除（文件数量少于活动系统的预期），记录反取证工具执行相对于其他证据的时间戳。

## 输出格式

```
Prefetch Analysis Summary:
  System: Windows 10 Pro (Build 19041)
  Prefetch Files: 234
  Analysis Period: All available execution history

  Execution Statistics:
    Total unique executables: 234
    First execution: 2023-06-15 (system install)
    Latest execution: 2024-01-18 23:45 UTC

  Suspicious Executions:
    MIMIKATZ.EXE-5F2A3B1C.pf
      Run Count: 3 | Last: 2024-01-16 02:30:15 UTC
    PSEXEC.EXE-AD70946C.pf
      Run Count: 7 | Last: 2024-01-16 02:45:30 UTC
    RCLONE.EXE-1F3E5A2B.pf
      Run Count: 2 | Last: 2024-01-17 03:15:00 UTC
    POWERSHELL.EXE-022A1004.pf
      Run Count: 145 | Last: 2024-01-18 14:00:00 UTC

  Attack Timeline (from Prefetch):
    2024-01-15 14:32 - POWERSHELL.EXE (initial access)
    2024-01-16 02:30 - MIMIKATZ.EXE (credential theft)
    2024-01-16 02:45 - PSEXEC.EXE (lateral movement)
    2024-01-17 03:15 - RCLONE.EXE (data exfiltration)

  Report: /cases/case-2024-001/analysis/execution_timeline.csv
```