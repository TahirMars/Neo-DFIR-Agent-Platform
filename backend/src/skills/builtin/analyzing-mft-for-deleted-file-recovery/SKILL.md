---
id: analyzing-mft-for-deleted-file-recovery
name: analyzing-mft-for-deleted-file-recovery
description: 分析 NTFS $MFT、$UsnJrnl、$LogFile 与 MFT slack，支撑删除文件恢复与时间线。
domain: cybersecurity
subdomain: digital-forensics
tags:
- mft
- ntfs
- deleted-files
- file-recovery
- mftecmd
- usn-journal
- logfile
- mft-slack-space
- file-system-forensics
- dfir
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
name_zh: 分析·MFT·已删除·文件·恢复
neo_agents:
- forensic
- general_chat
---

# 分析 MFT 以恢复已删除文件

## 概述

NTFS 主文件表（$MFT）是 NTFS 卷中每个文件和目录的核心元数据存储库。每个文件至少由一个 1024 字节的 MFT 记录表示，包含 $STANDARD_INFORMATION（时间戳、权限）、$FILE_NAME（名称、父目录、时间戳）和 $DATA（文件内容或簇运行指针）等属性。当文件被删除时，其 MFT 记录会被标记为非活动（清除 InUse 标志），但元数据会保留直到条目被新文件重新分配。这种持久性使 MFT 分析成为恢复已删除文件证据、重建文件系统时间线以及检测时间戳篡改等反取证活动的主要技术。

## 使用时机

- 当调查需要分析 MFT 以恢复已删除文件的安全事件时
- 当构建此领域的检测规则或威胁狩猎查询时
- 当 SOC 分析师需要此类分析的结构化流程时
- 当验证与此相关攻击技术的安全监控覆盖范围时

## 前置条件

- 取证磁盘镜像（E01、raw/dd、VMDK 或 VHDX 格式）
- MFTECmd（Eric Zimmerman）或 analyzeMFT（Python 实现）
- FTK Imager、Arsenal Image Mounter 或类似工具用于挂载镜像
- Timeline Explorer 或 Excel 用于 CSV 分析
- Python 3.8+ 用于自定义分析脚本
- 对 NTFS 文件系统内部结构的理解

## MFT 结构与记录布局

### MFT 记录头

每个 MFT 记录以签名 "FILE"（0x46494C45）开头，包含：

| 偏移量 | 大小 | 字段 |
|--------|------|-------|
| 0x00 | 4 字节 | 签名（"FILE"） |
| 0x04 | 2 字节 | 更新序列偏移量 |
| 0x06 | 2 字节 | 更新序列大小 |
| 0x08 | 8 字节 | $LogFile 序列号 |
| 0x10 | 2 字节 | 序列号 |
| 0x12 | 2 字节 | 硬链接计数 |
| 0x14 | 2 字节 | 第一个属性偏移量 |
| 0x16 | 2 字节 | 标志（0x01 = InUse，0x02 = 目录） |
| 0x18 | 4 字节 | MFT 记录已使用大小 |
| 0x1C | 4 字节 | MFT 记录分配大小 |
| 0x20 | 8 字节 | 基础文件记录引用 |
| 0x28 | 2 字节 | 下一个属性 ID |

### 关键 MFT 属性

| 类型 ID | 名称 | 描述 |
|---------|------|-------------|
| 0x10 | $STANDARD_INFORMATION | 时间戳、标志、所有者 ID、安全 ID |
| 0x30 | $FILE_NAME | 文件名、父 MFT 引用、时间戳 |
| 0x40 | $OBJECT_ID | 文件的唯一 GUID |
| 0x50 | $SECURITY_DESCRIPTOR | ACL 权限 |
| 0x60 | $VOLUME_NAME | 卷标签（仅卷元数据文件） |
| 0x80 | $DATA | 文件内容（小于 700 字节时为驻留数据）或簇运行列表 |
| 0x90 | $INDEX_ROOT | 目录的 B 树索引根 |
| 0xA0 | $INDEX_ALLOCATION | 大目录的 B 树索引条目 |
| 0xB0 | $BITMAP | 索引或 MFT 的分配位图 |

## 已删除文件恢复技术

### 技术 1：使用 MFTECmd 分析 MFT 记录

```powershell
# 使用 KAPE 或 FTK Imager 从取证镜像中提取 $MFT
# 用 MFTECmd 解析 $MFT
MFTECmd.exe -f "C:\Evidence\$MFT" --csv C:\Output --csvf mft_full.csv

# 在 Timeline Explorer 中过滤已删除文件（InUse = FALSE）
# 查找 InUse 列为 False 的条目
```

**在 CSV 输出中识别已删除文件：**
- `InUse` = False 表示已删除或重新分配的记录
- `ParentPath` 显示删除前的原始文件位置
- `FileSize` 显示原始大小（可能仍可恢复）
- $STANDARD_INFORMATION 和 $FILE_NAME 属性中的时间戳仍保留

### 技术 2：USN 日志（$UsnJrnl:$J）分析

USN 日志记录了 NTFS 卷中文件的所有更改，包括创建、删除、重命名和数据修改事件。

```powershell
# 用 MFTECmd 解析 USN 日志
MFTECmd.exe -f "C:\Evidence\$J" --csv C:\Output --csvf usn_journal.csv

# 关键 USN 原因代码用于删除证据：
# USN_REASON_FILE_DELETE     = 0x00000200
# USN_REASON_CLOSE           = 0x80000000
# USN_REASON_RENAME_OLD_NAME = 0x00001000
# USN_REASON_RENAME_NEW_NAME = 0x00002000
```

### 技术 3：$LogFile 事务分析

$LogFile 存储 NTFS 事务记录，即使 USN 日志已被循环，也能揭示文件操作。

```powershell
# 用 LogFileParser 解析 $LogFile
LogFileParser.exe -l "C:\Evidence\$LogFile" -o C:\Output

# 查找表示文件删除的 REDO 和 UNDO 操作：
# - DeallocateFileRecordSegment
# - DeleteAttribute
# - UpdateResidentValue（清除 InUse 标志）
```

### 技术 4：MFT 空闲空间分析

MFT 空闲空间存在于 MFT 记录已使用部分的末尾和分配的 1024 字节末尾之间。该区域可能包含先前文件记录的残余。

```python
import struct

def parse_mft_slack(mft_path: str, output_path: str):
    """提取并分析 MFT 空闲空间中的已删除文件残余。"""
    with open(mft_path, "rb") as f:
        record_size = 1024
        record_num = 0
        slack_findings = []

        while True:
            record = f.read(record_size)
            if len(record) < record_size:
                break

            # 验证 FILE 签名
            if record[:4] != b"FILE":
                record_num += 1
                continue

            # 从偏移量 0x18 获取已使用大小
            used_size = struct.unpack("<I", record[0x18:0x1C])[0]

            if used_size < record_size:
                slack = record[used_size:]
                # 检查空闲空间是否包含可读字符串或属性头
                if any(c > 0x20 and c < 0x7F for c in slack[:50]):
                    slack_findings.append({
                        "record": record_num,
                        "used_size": used_size,
                        "slack_size": record_size - used_size,
                        "slack_preview": slack[:100].hex()
                    })

            record_num += 1

    return slack_findings
```

## 与关联工件的交叉验证

### 与 $Recycle.Bin 交叉参考

```powershell
# 用 RBCmd 解析回收站
RBCmd.exe -d "C:\Evidence\$Recycle.Bin" --csv C:\Output --csvf recycle_bin.csv

# 关联：$I 文件包含原始路径和删除时间戳
# 将 $R 文件中的 MFT 条目号匹配回原始 MFT 记录
```

### 与卷影副本交叉参考

```powershell
# 列出卷影副本
vssadmin list shadows

# 挂载卷影副本并从每个副本提取 $MFT
# 跨卷影副本比较 MFT 记录以跟踪文件变更历史
```

## 取证价值

- **已删除文件元数据恢复**：原始文件名、路径、大小和时间戳
- **时间线重建**：文件创建、修改、访问和删除事件
- **时间戳篡改检测**：比较 $SI 与 $FN 时间戳
- **数据雕刻指导**：MFT 簇运行指向磁盘上的文件内容
- **反取证检测**：识别被擦除或篡改的 MFT 记录

## 参考资料

- NTFS MFT 高级取证分析：https://www.deaddisk.com/posts/ntfs-mft-advanced-forensic-analysis-guide/
- MFT 空闲空间的取证价值：https://www.sygnia.co/blog/the-forensic-value-of-mft-slack-space/
- MFTECmd 文档：https://ericzimmerman.github.io/
- SANS FOR500: Windows 取证分析

## 示例输出

```text
$ MFTECmd.exe -f "C:\Evidence\$MFT" --csv /analysis/mft_output

MFTECmd v1.2.2 - MFT 解析器
==============================
输入：C:\Evidence\$MFT（大小：384 MB）
总 MFT 条目：395,264

解析 MFT 条目... 完成（12.4 秒）

--- 已删除文件恢复摘要 ---
总条目数：          395,264
活动文件：           245,832
已删除文件：          149,432
  可恢复：          87,234（驻留数据或未重新分配的簇）
  部分可恢复：      31,456（部分簇被覆盖）
  不可恢复：         30,742（所有簇已重新分配）

--- 最近删除的文件（事件窗口：2024-01-15 至 2024-01-18） ---
MFT 条目 | 文件名                          | 路径                               | 大小      | 删除时间（UTC）         | 可恢复性
----------|-----------------------------------|------------------------------------|-----------|-----------------------|------------
148923    | exfil_tool.exe                    | C:\ProgramData\Updates\            | 1,258,496 | 2024-01-17 02:45:12   | YES
148924    | exfil_tool.log                    | C:\ProgramData\Updates\            | 45,312    | 2024-01-17 02:45:14   | YES
149001    | passwords.txt                     | C:\Users\jsmith\Desktop\           | 2,048     | 2024-01-17 02:50:33   | YES
149150    | scan_results.csv                  | C:\Users\jsmith\AppData\Local\Temp | 892,416   | 2024-01-17 03:00:01   | PARTIAL
149200    | mimikatz.exe                      | C:\Windows\Temp\                   | 1,250,816 | 2024-01-18 01:15:22   | YES
149201    | sekurlsa.log                      | C:\Windows\Temp\                   | 32,768    | 2024-01-18 01:15:25   | YES
149302    | .bash_history                     | C:\Users\jsmith\                   | 4,096     | 2024-01-18 03:00:00   | NO
149400    | ClearEventLogs.ps1                | C:\Windows\Temp\                   | 1,536     | 2024-01-18 03:01:12   | YES

--- $STANDARD_INFORMATION 与 $FILE_NAME 时间戳分析（时间戳篡改检测） ---
MFT 条目 | 文件名            | $SI 创建时间          | $FN 创建时间          | 差值     | 判定
----------|---------------------|----------------------|----------------------|-----------|----------
148923    | exfil_tool.exe      | 2023-06-15 10:00:00  | 2024-01-15 14:34:02  | -214 天 | TIMESTOMPED
149200    | mimikatz.exe        | 2022-01-01 00:00:00  | 2024-01-16 02:30:15  | -745 天 | TIMESTOMPED

已恢复文件导出到：/analysis/mft_output/recovered/
完整 CSV 报告：/analysis/mft_output/mft_analysis.csv（395,264 行）
时间线 CSV：/analysis/mft_output/mft_timeline.csv
```