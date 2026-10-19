---
id: analyzing-slack-space-and-file-system-artifacts
name: analyzing-slack-space-and-file-system-artifacts
name_zh: 分析·Slack·空间·与·文件·系统·取证痕迹
description: 检查NTFS卷上的文件系统闲置空间、主文件表(MFT)条目、USN变更日志和备用数据流，以恢复隐藏数据并重建文件活动记录。使用Sleuth
  Kit、MFTECmd等工具进行取证分析，识别反取证行为和潜在恶意痕迹。
domain: cybersecurity
subdomain: digital-forensics
tags:
- forensics
- slack-space
- ntfs
- mft
- usn-journal
- alternate-data-streams
- file-system-analysis
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 分析·Slack·空间·与·文件·系统·取证痕迹

## 使用时机
- 在NTFS文件系统闲置空间中搜索隐藏或残留数据时
- 用于分析已删除文件元数据的主文件表(MFT)条目
- 从USN变更日志重建文件操作时
- 用于检测通过备用数据流(ADS)隐藏数据或恶意软件
- 在深度取证分析过程中，需要进行标准文件恢复之外的检查

## 前置条件
- NTFS文件系统的取证磁盘映像
- Sleuth Kit (TSK)工具：istat、icat、fls、blkls、blkstat
- Eric Zimmerman开发的MFTECmd用于MFT解析
- MFTExplorer用于交互式MFT分析
- 了解NTFS结构（MFT、$UsnJrnl、$LogFile、ADS）
- 带有analyzeMFT或mft库的Python用于自动解析

## 工作流程
### 第1步：识别并提取NTFS文件系统工件

```bash
# Determine partition layout
mmls /cases/case-2024-001/images/evidence.dd

# Extract key NTFS system files
# $MFT - Master File Table
icat -o 2048 /cases/case-2024-001/images/evidence.dd 0 > /cases/case-2024-001/ntfs/MFT

# $UsnJrnl:$J - USN Change Journal
icat -o 2048 /cases/case-2024-001/images/evidence.dd 62-128 > /cases/case-2024-001/ntfs/UsnJrnl_J

# $LogFile - Transaction log
icat -o 2048 /cases/case-2024-001/images/evidence.dd 2 > /cases/case-2024-001/ntfs/LogFile

# Extract all slack space from the volume
blkls -s -o 2048 /cases/case-2024-001/images/evidence.dd > /cases/case-2024-001/ntfs/slack_space.raw

# Get file system information
fsstat -o 2048 /cases/case-2024-001/images/evidence.dd | tee /cases/case-2024-001/ntfs/fs_info.txt
```
### 第2步：分析主文件表（MFT）

```bash
# Parse MFT with MFTECmd (Eric Zimmerman)
MFTECmd.exe -f "C:\cases\ntfs\MFT" --csv "C:\cases\analysis\" --csvf mft_analysis.csv

# Parse with analyzeMFT (Python)
pip install analyzeMFT

analyzeMFT.py -f /cases/case-2024-001/ntfs/MFT \
   -o /cases/case-2024-001/analysis/mft_analysis.csv \
   -c

# Custom MFT analysis with Python
python3 << 'PYEOF'
from mft import PyMft
import csv

mft = PyMft(open('/cases/case-2024-001/ntfs/MFT', 'rb').read())

deleted_files = []
suspicious_files = []

for entry in mft.entries():
    if entry is None:
        continue

    filename = entry.get_filename()
    if filename is None:
        continue

    is_deleted = not entry.is_active()
    is_directory = entry.is_directory()
    created = entry.get_created_timestamp()
    modified = entry.get_modified_timestamp()
    mft_modified = entry.get_mft_modified_timestamp()
    size = entry.get_file_size()

    # Flag deleted files for recovery
    if is_deleted and not is_directory and size > 0:
        deleted_files.append({
            'filename': filename,
            'size': size,
            'created': str(created),
            'modified': str(modified),
            'entry_number': entry.entry_number
        })

    # Detect timestomping (MFT modified time != $SI modified time)
    si_modified = entry.get_si_modified_timestamp()
    fn_modified = entry.get_fn_modified_timestamp()
    if si_modified and fn_modified:
        if abs((si_modified - fn_modified).total_seconds()) > 86400:  # >1 day difference
            suspicious_files.append({
                'filename': filename,
                'si_modified': str(si_modified),
                'fn_modified': str(fn_modified),
                'delta': str(si_modified - fn_modified)
            })

print(f"=== DELETED FILES (recoverable metadata) ===")
print(f"Total: {len(deleted_files)}")
for f in deleted_files[:20]:
    print(f"  [{f['modified']}] {f['filename']} ({f['size']} bytes)")

print(f"\n=== POTENTIAL TIMESTOMPING ===")
print(f"Total suspicious: {len(suspicious_files)}")
for f in suspicious_files[:10]:
    print(f"  {f['filename']}: $SI={f['si_modified']}, $FN={f['fn_modified']} (delta: {f['delta']})")
PYEOF
```
### 第3步：分析Slack空间中的隐藏数据

```bash
# Search slack space for strings
strings -a /cases/case-2024-001/ntfs/slack_space.raw > /cases/case-2024-001/analysis/slack_strings.txt

# Search for specific patterns in slack space
grep -iab "password\|secret\|confidential\|credit.card\|ssn" \
   /cases/case-2024-001/ntfs/slack_space.raw > /cases/case-2024-001/analysis/slack_keywords.txt

# Analyze individual file slack
python3 << 'PYEOF'
import struct

# File slack consists of:
# 1. RAM slack: bytes between file end and next sector boundary (filled with RAM content or zeros)
# 2. Drive slack: remaining sectors in the cluster after the last file sector

# Analyze slack for specific MFT entries
# Using Sleuth Kit to get file slack for a specific file
import subprocess

# Get file details
result = subprocess.run(
    ['istat', '-o', '2048', '/cases/case-2024-001/images/evidence.dd', '14523'],
    capture_output=True, text=True
)
print(result.stdout)

# The output shows data runs - the last cluster may contain slack data
# Calculate slack size: (allocated_size - file_size) bytes
PYEOF
```

# Search for file signatures in slack space (embedded files)
foremost -t jpg,pdf,zip -i /cases/case-2024-001/ntfs/slack_space.raw \
   -o /cases/case-2024-001/carved/slack_carved/

# Use bulk_extractor to find structured data in slack
bulk_extractor -o /cases/case-2024-001/analysis/bulk_extract/ \
   /cases/case-2024-001/ntfs/slack_space.raw
```
### 第4步：解析USN变更日志

```bash
# Parse USN Journal with MFTECmd
MFTECmd.exe -f "C:\cases\ntfs\UsnJrnl_J" --csv "C:\cases\analysis\" --csvf usn_journal.csv

# Python USN Journal parsing
pip install pyusn

python3 << 'PYEOF'
import struct
import csv
from datetime import datetime, timedelta

def parse_usn_record(data, offset):
    """Parse a single USN_RECORD_V2."""
    if offset + 8 > len(data):
        return None, offset

    record_len = struct.unpack_from('<I', data, offset)[0]
    if record_len < 56 or record_len > 65536 or offset + record_len > len(data):
        return None, offset + 8

    major_ver = struct.unpack_from('<H', data, offset + 4)[0]
    if major_ver != 2:
        return None, offset + record_len

    mft_ref = struct.unpack_from('<Q', data, offset + 8)[0] & 0xFFFFFFFFFFFF
    parent_ref = struct.unpack_from('<Q', data, offset + 16)[0] & 0xFFFFFFFFFFFF
    usn = struct.unpack_from('<Q', data, offset + 24)[0]
    timestamp = struct.unpack_from('<Q', data, offset + 32)[0]
    reason = struct.unpack_from('<I', data, offset + 40)[0]
    source_info = struct.unpack_from('<I', data, offset + 44)[0]
    security_id = struct.unpack_from('<I', data, offset + 48)[0]
    file_attrs = struct.unpack_from('<I', data, offset + 52)[0]
    filename_len = struct.unpack_from('<H', data, offset + 56)[0]
    filename_off = struct.unpack_from('<H', data, offset + 58)[0]

    name = data[offset + filename_off:offset + filename_off + filename_len].decode('utf-16-le', errors='ignore')

    # Convert Windows FILETIME to datetime
    ts = datetime(1601, 1, 1) + timedelta(microseconds=timestamp // 10)

    # Decode reason flags
    reasons = []
    reason_flags = {
        0x01: 'DATA_OVERWRITE', 0x02: 'DATA_EXTEND', 0x04: 'DATA_TRUNCATION',
        0x10: 'NAMED_DATA_OVERWRITE', 0x20: 'NAMED_DATA_EXTEND',
        0x100: 'FILE_CREATE', 0x200: 'FILE_DELETE', 0x400: 'EA_CHANGE',
        0x800: 'SECURITY_CHANGE', 0x1000: 'RENAME_OLD_NAME', 0x2000: 'RENAME_NEW_NAME',
        0x4000: 'INDEXABLE_CHANGE', 0x8000: 'BASIC_INFO_CHANGE',
        0x10000: 'HARD_LINK_CHANGE', 0x20000: 'COMPRESSION_CHANGE',
        0x40000: 'ENCRYPTION_CHANGE', 0x80000: 'OBJECT_ID_CHANGE',
        0x100000: 'REPARSE_POINT_CHANGE', 0x200000: 'STREAM_CHANGE',
        0x80000000: 'CLOSE'
    }
    for flag, desc in reason_flags.items():
        if reason & flag:
            reasons.append(desc)

    record = {
        'timestamp': ts.strftime('%Y-%m-%d %H:%M:%S'),
        'filename': name,
        'mft_entry': mft_ref,
        'parent_entry': parent_ref,
        'reasons': '|'.join(reasons),
        'usn': usn
    }

    return record, offset + record_len

# Parse the journal
with open('/cases/case-2024-001/ntfs/UsnJrnl_J', 'rb') as f:
    data = f.read()

records = []
offset = 0
while offset < len(data) - 8:
    record, offset = parse_usn_record(data, offset)
    if record:
        records.append(record)
    else:
        offset += 8  # Skip zeros

# Filter for deletion events
deletions = [r for r in records if 'FILE_DELETE' in r['reasons']]
creations = [r for r in records if 'FILE_CREATE' in r['reasons']]
renames = [r for r in records if 'RENAME_NEW_NAME' in r['reasons']]

print(f"Total USN records: {len(records)}")
print(f"File creations: {len(creations)}")
print(f"File deletions: {len(deletions)}")
print(f"File renames: {len(renames)}")

print("\n=== RECENT DELETIONS ===")
for r in deletions[-20:]:
    print(f"  [{r['timestamp']}] DELETED: {r['filename']} (MFT#{r['mft_entry']})")

# Write full journal to CSV
with open('/cases/case-2024-001/analysis/usn_journal.csv', 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['timestamp', 'filename', 'mft_entry', 'parent_entry', 'reasons', 'usn'])
    writer.writeheader()
    writer.writerows(records)
PYEOF
```
### 第5步：检测和分析备用数据流

```bash
# List all Alternate Data Streams in the image
find /mnt/evidence -exec getfattr -d {} \; 2>/dev/null | grep -i "ads\|zone\|stream"

# Using Sleuth Kit to find ADS
fls -r -o 2048 /cases/case-2024-001/images/evidence.dd | grep ":" | \
   tee /cases/case-2024-001/analysis/ads_list.txt

# Extract specific ADS content
# Format: icat image inode:ads_name
icat -o 2048 /cases/case-2024-001/images/evidence.dd 14523:hidden_stream \
   > /cases/case-2024-001/analysis/extracted_ads.bin

# Check Zone.Identifier streams (download origin tracking)
fls -r -o 2048 /cases/case-2024-001/images/evidence.dd | grep "Zone.Identifier" | \
   while read line; do
       inode=$(echo "$line" | awk '{print $2}' | tr -d ':')
       echo "=== $line ==="
       icat -o 2048 /cases/case-2024-001/images/evidence.dd "${inode}:Zone.Identifier" 2>/dev/null
       echo ""
   done > /cases/case-2024-001/analysis/zone_identifiers.txt

# Zone.Identifier content reveals:
# [ZoneTransfer]
# ZoneId=3          (3 = Internet, indicating file was downloaded)
# ReferrerUrl=https://malicious-site.com/payload.exe
# HostUrl=https://cdn.malicious-site.com/payload.exe
```
## 关键概念

| 概念 | 描述 |
|---------|-------------|
| 文件松弛 | 文件尾和包含残留数据的簇边界之间未使用的空间 |
| 内存闲置 | 从文件末尾到扇区边界的松弛部分（历史上充满RAM）|
| MFT ($MFT) | 主文件表 - NTFS元数据数据库，包含每个文件的条目 |
| USN日志 ($UsnJrnl) | 记录NTFS上所有文件/目录修改的日志 |
| 备用数据流 | NTFS功能允许每个文件多个数据流（隐藏存储）|
| $STANDARD_INFORMATION | $STANDARD_INFORMATION具有可由用户模式应用程序修改的时间戳的MFT属性 |
| $FILE_NAME | 带有只能由内核修改的时间戳的MFT属性 |
| 时代踩踏 | 反取证技术修改文件时间戳以避免检测 |

## 工具和系统

| 工具 | 目的 |
|------|---------|
| MFTECmd | Eric Zimmerman MFT和USN日志解析器，带CSV输出 |
| MFT浏览器 | 用于MFT分析的交互式GUI工具 |
| analyzeMFT | 具有CSV/JSON输出的Python MFT解析器 |
| Sleuth Kit | 文件系统取证工具包（fls、icat、blkls、istat）|
| bulk_extractor | 从原始数据（包括松弛空间）中提取特征 |
| NTFS日志跟踪器 | 解析$LogFile交易记录的工具 |
| streams.exe | 用于列出NTFS备用数据流的Sysinternals工具 |
| Plaso | 解析MFT和USN日志的超级时间轴工具 |

## 常见场景

**场景1：通过时间戳进行反取证检测**  
将MFT条目中的$STANDARD_INFORMATION时间戳与$FILE_NAME时间戳进行比较，标记$SI时间戳早于$FN时间戳的文件（在正常操作中不可能），将时间戳文件识别为故意操纵的证据，与其他时间线证据相关联。

**场景2：备用数据流中的隐藏数据**  
扫描附加到标准区域之外的文件的ADS。标识符，提取ADS内容进行分析，检查ADS中存储的隐藏可执行文件或文档，将ADS创建与用户活动时间线相关联，记录结果以获取证据。

**场景3：从MFT重建删除的文件**  
解析MFT以查找非活动（已删除）条目，提取已删除文件的文件名、大小和时间戳，如果数据簇未被覆盖，则使用icat恢复文件内容，构建已删除证据文件列表，与USN日志删除事件关联。

**场景4：从USN日志重建文件活动**  
解析调查期间的USN变更日志，识别文件创建、修改、重命名和删除事件，重建文件操作序列，检测数据暂存证据（创建、复制、压缩、删除模式），识别反取证文件擦除。

## 输出格式

```
File System Artifact Analysis:
  Volume: NTFS (Partition 2, 465 GB)
  Cluster Size: 4096 bytes

  MFT Analysis:
    Total Entries: 456,789
    Active Files: 234,567
    Deleted Entries: 12,345 (8,901 with recoverable metadata)
    Timestomped Files: 23 (SI/FN mismatch detected)

  USN Journal:
    Records Parsed: 2,345,678
    Date Range: 2024-01-01 to 2024-01-20
    File Creations: 45,678
    File Deletions: 23,456
    File Renames: 12,345

  Alternate Data Streams:
    Total ADS Found: 1,234
    Zone.Identifier: 890 (downloaded files)
    Custom/Suspicious ADS: 5 (hidden data detected)

  Slack Space:
    Total Slack: 12.3 GB
    Keyword Hits: 45 (passwords, credit cards)
    Carved Files: 23 from slack space

  Suspicious Findings:
    - 23 files with timestomped timestamps
    - 5 files with hidden ADS containing data
    - USN shows mass deletion on 2024-01-18 (anti-forensics)
    - Slack space contains residual email fragments

  Reports: /cases/case-2024-001/analysis/
```