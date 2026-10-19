---
id: analyzing-windows-lnk-files-for-artifacts
name: analyzing-windows-lnk-files-for-artifacts
name_zh: 分析·Windows·LNK·文件·取证痕迹
description: 本技能「分析·Windows·LNK·文件·取证痕迹」（标识 analyzing-windows-lnk-files-for-artifacts）面向网络安全检测、分析与响应场景；操作步骤、命令与脚本见正文及
  scripts/、references/ 目录。涉及第三方 API、CLI 与产品名称处保留英文。请在授权与组织策略允许范围内使用。
domain: cybersecurity
subdomain: digital-forensics
tags:
- forensics
- lnk-files
- windows-artifacts
- shortcut-analysis
- timeline-reconstruction
- evidence-collection
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 分析 Windows LNK 文件取证痕迹

## 使用时机
- 从 Windows 快捷方式文件重建用户文件访问历史记录时
- 用于追踪访问的文件、网络共享和可移动媒体
- 在调查期间证明用户打开了特定文档
- 将文件访问与其他时间线工件关联时
- 用于识别远程系统或 USB 设备上的访问路径

## 前置条件
- 从取证镜像访问 LNK 文件（最近、桌面、快速启动）
- 使用 LECmd (Eric Zimmerman)、python-lnk 或 LnkParser 进行分析
- 了解 LNK 文件结构（Shell Link 二进制格式）
- 了解 Windows 系统上的 LNK 文件位置
- 配备分析工具的取证工作站

## 工作流程
### 第 1 步：从取证镜像中收集 LNK 文件

```bash
# Mount forensic image
mount -o ro,loop,offset=$((2048*512)) /cases/case-2024-001/images/evidence.dd /mnt/evidence

mkdir -p /cases/case-2024-001/lnk/{recent,desktop,startup,custom}

# Copy Recent items LNK files (primary source)
cp /mnt/evidence/Users/*/AppData/Roaming/Microsoft/Windows/Recent/*.lnk \
   /cases/case-2024-001/lnk/recent/ 2>/dev/null

# Copy automatic destinations (Jump Lists)
cp /mnt/evidence/Users/*/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/*.automaticDestinations-ms \
   /cases/case-2024-001/lnk/recent/ 2>/dev/null

# Copy custom destinations (pinned Jump List items)
cp /mnt/evidence/Users/*/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations/*.customDestinations-ms \
   /cases/case-2024-001/lnk/custom/ 2>/dev/null

# Copy Desktop shortcuts
cp /mnt/evidence/Users/*/Desktop/*.lnk /cases/case-2024-001/lnk/desktop/ 2>/dev/null

# Copy Startup folder shortcuts (persistence)
cp /mnt/evidence/Users/*/AppData/Roaming/Microsoft/Windows/Start\ Menu/Programs/Startup/*.lnk \
   /cases/case-2024-001/lnk/startup/ 2>/dev/null
cp "/mnt/evidence/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup"/*.lnk \
   /cases/case-2024-001/lnk/startup/ 2>/dev/null

# Find all LNK files on the system
find /mnt/evidence/ -name "*.lnk" -type f 2>/dev/null > /cases/case-2024-001/lnk/all_lnk_locations.txt

# Count and hash
ls /cases/case-2024-001/lnk/recent/ | wc -l
sha256sum /cases/case-2024-001/lnk/recent/*.lnk > /cases/case-2024-001/lnk/lnk_hashes.txt 2>/dev/null
```

### 第 2 步：使用 LECmd 解析 LNK 文件

```bash
# Using Eric Zimmerman's LECmd (Windows or via Mono)
# Process all LNK files in a directory
LECmd.exe -d "C:\cases\lnk\recent\" --csv "C:\cases\analysis\" --csvf lnk_analysis.csv

# Process a single LNK file with verbose output
LECmd.exe -f "C:\cases\lnk\recent\document.pdf.lnk"

# Process Jump List files
JLECmd.exe -d "C:\cases\lnk\recent\" --csv "C:\cases\analysis\" --csvf jumplist_analysis.csv

# Output includes:
# - Source file path
# - Target path (file that was accessed)
# - Target creation, modification, access timestamps
# - LNK creation and modification timestamps
# - Working directory
# - Command line arguments
# - Volume serial number and label
# - Drive type (Fixed, Removable, Network)
# - Machine ID (NetBIOS name)
# - MAC address (from tracker database)
# - File size of target
```

### 第 3 步：使用 Python 解析 LNK 文件

```bash
pip install LnkParse3

python3 << 'PYEOF'
import LnkParse3
import os, json, csv
from datetime import datetime

lnk_dir = '/cases/case-2024-001/lnk/recent/'
results = []

for filename in sorted(os.listdir(lnk_dir)):
    if not filename.lower().endswith('.lnk'):
        continue

    filepath = os.path.join(lnk_dir, filename)
    try:
        with open(filepath, 'rb') as f:
            lnk = LnkParse3.lnk_file(f)
            info = lnk.get_json()

            parsed = {
                'lnk_file': filename,
                'target_path': '',
                'working_dir': '',
                'arguments': '',
                'target_created': '',
                'target_modified': '',
                'target_accessed': '',
                'file_size': '',
                'drive_type': '',
                'volume_serial': '',
                'volume_label': '',
                'machine_id': '',
                'mac_address': '',
            }

            # Extract header timestamps
            header = info.get('header', {})
            parsed['target_created'] = str(header.get('creation_time', ''))
            parsed['target_modified'] = str(header.get('modified_time', ''))
            parsed['target_accessed'] = str(header.get('accessed_time', ''))
            parsed['file_size'] = str(header.get('file_size', ''))

            # Extract link info
            link_info = info.get('link_info', {})
            if link_info:
                local_path = link_info.get('local_base_path', '')
                network_path = link_info.get('common_network_relative_link', {}).get('net_name', '')
                parsed['target_path'] = local_path or network_path

                vol_info = link_info.get('volume_id', {})
                if vol_info:
                    parsed['drive_type'] = str(vol_info.get('drive_type', ''))
                    parsed['volume_serial'] = str(vol_info.get('drive_serial_number', ''))
                    parsed['volume_label'] = str(vol_info.get('volume_label', ''))

            # Extract string data
            string_data = info.get('string_data', {})
            parsed['working_dir'] = str(string_data.get('working_dir', ''))
            parsed['arguments'] = str(string_data.get('command_line_arguments', ''))

            # Extract tracker data (machine ID and MAC)
            extra = info.get('extra', {})
            tracker = extra.get('DISTRIBUTED_LINK_TRACKER_BLOCK', {})
            if tracker:
                parsed['machine_id'] = str(tracker.get('machine_id', ''))
                parsed['mac_address'] = str(tracker.get('mac_address', ''))

            results.append(parsed)

            # Print summary
            print(f"\n{filename}")
            print(f"  Target: {parsed['target_path']}")
            print(f"  Modified: {parsed['target_modified']}")
            print(f"  Drive: {parsed['drive_type']} (Serial: {parsed['volume_serial']})")
            if parsed['machine_id']:
                print(f"  Machine: {parsed['machine_id']}")

    except Exception as e:
        print(f"  Error parsing {filename}: {e}")

# Write results to CSV
with open('/cases/case-2024-001/analysis/lnk_analysis.csv', 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=results[0].keys() if results else [])
    writer.writeheader()
    writer.writerows(results)

print(f"\n\nTotal LNK files parsed: {len(results)}")
PYEOF
```

### 第 4 步：分析调查价值

```bash
# Identify files accessed from removable media
python3 << 'PYEOF'
import csv

with open('/cases/case-2024-001/analysis/lnk_analysis.csv') as f:
    reader = csv.DictReader(f)

    print("=== FILES ACCESSED FROM REMOVABLE MEDIA ===\n")
    removable = []
    network = []

    for row in reader:
        if 'DRIVE_REMOVABLE' in row.get('drive_type', '').upper() or \
           'removable' in row.get('drive_type', '').lower():
            removable.append(row)
            print(f"  {row['target_modified']} | {row['target_path']} | Vol: {row['volume_serial']}")

        if 'network' in row.get('drive_type', '').lower() or \
           row.get('target_path', '').startswith('\\\\'):
            network.append(row)

    print(f"\n=== FILES ACCESSED FROM NETWORK SHARES ===\n")
    for row in network:
        print(f"  {row['target_modified']} | {row['target_path']}")

    print(f"\nRemovable media files: {len(removable)}")
    print(f"Network share files: {len(network)}")

    # Check for unique machines (tracker data)
    machines = set()
    for row in [*removable, *network]:
        if row.get('machine_id'):
            machines.add(row['machine_id'])
    if machines:
        print(f"\nMachine IDs found: {machines}")
PYEOF

# Check Startup folder LNK files for persistence
echo "=== STARTUP FOLDER SHORTCUTS (PERSISTENCE) ===" > /cases/case-2024-001/analysis/startup_persistence.txt
for lnk in /cases/case-2024-001/lnk/startup/*.lnk; do
    python3 -c "
import LnkParse3
with open('$lnk', 'rb') as f:
    lnk = LnkParse3.lnk_file(f)
    info = lnk.get_json()
    target = info.get('link_info', {}).get('local_base_path', 'Unknown')
    args = info.get('string_data', {}).get('command_line_arguments', '')
    print(f'  $(basename $lnk): {target} {args}')
" >> /cases/case-2024-001/analysis/startup_persistence.txt 2>/dev/null
done
```

## 关键概念

| 概念 | 说明 |
|---------|-------------|
| Shell 链接（.lnk） | Windows 快捷方式格式，含目标路径、时间戳与元数据 |
| 目标时间戳 | 快捷方式所指向文件的创建、修改与访问时间 |
| 卷序列号 | 目标文件所在卷的唯一标识 |
| 机器 ID | 分布式链接跟踪服务写入的 NetBIOS 名 |
| MAC 地址 | 创建该 LNK 的机器网卡 MAC |
| 跳转列表（Jump Lists） | 各应用程序的最近与固定文件列表（内嵌 LNK 数据） |
| Automatic Destinations | 系统维护的、最近打开文件的跳转列表项 |
| Custom Destinations | 用户固定的跳转列表项，直至手动移除 |

## 工具与系统

| 工具 | 用途 |
|------|---------|
| LECmd | Eric Zimmerman 命令行 LNK 解析器，支持 CSV/JSON 输出 |
| JLECmd | Eric Zimmerman 跳转列表解析器 |
| LnkParse3 | 用于编程解析 LNK 的 Python 库 |
| lnk_parser | 另一款 Python LNK 解析工具 |
| Autopsy | 带 LNK 分析模块的取证平台 |
| KAPE | 自动化采集 LNK 与跳转列表工件 |
| Plaso | 含 LNK 解析器、用于超级时间线的工具 |
| LNK Explorer | 交互式查看 LNK 的 GUI 工具 |

## 常见场景

**场景 1：经 U 盘的数据外泄**  
分析「最近」文件夹中指向可移动介质的 LNK，将卷序列号与 USBSTOR 注册表项关联，列出自 U 盘访问的文件，确认在可移动盘上打开过的文档，并与复制时间戳关联。

**场景 2：通过「启动」快捷方式的恶意持久化**  
检查「启动」文件夹 LNK 的目标是否恶意，查看目标路径与参数是否含编码命令或可疑可执行文件，核实目标文件是否存在并做进一步分析，将创建时间与初次失陷时间关联。

**场景 3：网络共享访问调查**  
筛选含 UNC 路径的 LNK，识别访问过的共享与时间，将机器 ID 与已知企业资产对照，检查是否在职责外访问敏感文件服务器，构建合规调查用访问时间线。

**场景 4：法律程序所需的文档访问时间线**  
提取「最近」文件夹全部 LNK，按时间列出用户访问的文档，标出与案件相关的文件，用目标时间戳说明打开时间，并与邮件等通信时间线交叉验证。

## 输出格式

```
LNK 分析摘要:
  用户配置文件: suspect_user
  LNK 总数: 234（最近: 198，桌面: 23，启动: 5，其他: 8）

  文件访问统计:
    本地盘 (C:):    156 个文件
    可移动介质:     23 个文件（3 个不同卷序列号）
    网络共享:      15 个文件（\\server01, \\fileserver）
    其他盘:        4 个文件

  发现的机器 ID: DESKTOP-ABC123, LAPTOP-XYZ789
  MAC 地址: AA:BB:CC:DD:EE:FF, 11:22:33:44:55:66

  可移动介质访问:
    卷序列号 1234-ABCD:
      2024-01-15 14:32 - E:\Confidential\financial_report.xlsx
      2024-01-15 14:45 - E:\Confidential\customer_database.csv
      2024-01-15 15:00 - E:\Projects\source_code.zip

  启动项持久化:
    updater.lnk -> C:\ProgramData\svc\updater.exe（可疑）
    OneDrive.lnk -> C:\Users\...\OneDrive.exe（正常）

  时间线: /cases/case-2024-001/analysis/lnk_analysis.csv
```