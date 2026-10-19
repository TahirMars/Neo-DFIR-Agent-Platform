---
id: hunting-for-defense-evasion-via-timestomping
name: hunting-for-defense-evasion-via-timestomping
name_zh: 威胁狩猎·防御·规避·时间戳篡改
description: 通过比对 MFT 中 $STANDARD_INFORMATION 与 $FILE_NAME 时间戳检测 NTFS 时间篡改（MITRE T1070.006）。使用
  analyzeMFT 与 Python 识别具有异常时间模式、表明反取证时间戳篡改活动的文件。
domain: cybersecurity
subdomain: threat-hunting
tags:
- timestomping
- ntfs-forensics
- mft-analysis
- defense-evasion
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 威胁狩猎·防御·规避·时间戳篡改

通过分析 NTFS MFT 项中 $STANDARD_INFORMATION 与 $FILE_NAME 属性之间的不一致，检测时间戳篡改。

## 使用时机

- 调查疑似反取证活动：对手可能篡改文件时间戳以使恶意软件混入合法目录
- 在沦陷 Windows 系统上针对防御规避（MITRE ATT&CK T1070.006）进行威胁猎杀
- 在磁盘镜像或现场取证的法医检验中验证时间线完整性
- 分拣创建日期看似早于系统安装或与已知部署时间线不一致的可疑文件
- 检测 Timestomp（Metasploit）、NTimeStomp、SetMACE 或 PowerShell Set-ItemProperty 等篡改工具
- 构建自动化检测流水线，标记 MFT 数据中的时间异常供 SOC 分析

**请勿作为** 唯一检测手段；高阶对手可同时篡改 $STANDARD_INFORMATION 与 $FILE_NAME 时间戳（后者需原始磁盘访问，难度更高）。应与 USN 日志、$LogFile 及 ShimCache/Amcache 分析结合佐证。

## 前置条件

- 从 Windows 系统提取的原始 $MFT 文件（经 FTK Imager、KAPE 或现场提取）
- 用于解析 MFT 的 `MFTECmd`（Eric Zimmerman 工具）或 `analyzeMFT`
- Python 3.8+ 及用于分析的 `pandas`
- 可选：`mft` Python 库（`pip install mft`）以编程解析 MFT
- 可选：KAPE（Kroll Artifact Parser and Extractor）用于自动化工件采集
- Timeline Explorer 或 Excel，用于解析后 MFT 输出的可视化分析

## 工作流程

### 第 1 步：从现场系统或磁盘镜像提取 $MFT

```powershell
# Method 1: Using KAPE to collect MFT and related artifacts
.\kape.exe --tsource C: --tdest D:\Evidence\MFT_Collection --target !SANS_Triage

# Method 2: Using FTK Imager CLI to extract $MFT
ftkimager.exe \\.\C: D:\Evidence\mft_raw.bin --e01 --include $MFT

# Method 3: Raw copy using RawCopy (handles locked NTFS system files)
RawCopy.exe /FileNamePath:C:0 /OutputPath:D:\Evidence\ /OutputName:$MFT
```

```bash
# Method 4: On a mounted forensic image in Linux
sudo mount -o ro,norecovery /dev/sdb1 /mnt/evidence
sudo icat -o 2048 /dev/sdb 0 > /mnt/output/$MFT

# Method 5: Using sleuthkit to extract MFT from disk image
icat -o 2048 evidence.E01 0 > extracted_MFT
```### 第 2 步：使用 MFTECmd 解析 MFT

使用 Eric Zimmerman 的 MFTECmd 生成同时包含 $STANDARD_INFORMATION 与 $FILE_NAME 时间戳的 CSV：```powershell
# Parse MFT to CSV with all timestamp columns
MFTECmd.exe -f "D:\Evidence\$MFT" --csv D:\Evidence\Parsed\ --csvf mft_parsed.csv

# The output CSV contains these critical columns:
# Created0x10         - $STANDARD_INFORMATION Created timestamp
# LastModified0x10    - $STANDARD_INFORMATION Modified timestamp
# LastAccess0x10      - $STANDARD_INFORMATION Accessed timestamp
# LastRecordChange0x10 - $STANDARD_INFORMATION Entry Modified timestamp
# Created0x30         - $FILE_NAME Created timestamp
# LastModified0x30    - $FILE_NAME Modified timestamp
# LastAccess0x30      - $FILE_NAME Accessed timestamp
# LastRecordChange0x30 - $FILE_NAME Entry Modified timestamp
```### 第 3 步：通过 SI 与 FN 比对检测时间戳篡改

核心检测逻辑：$STANDARD_INFORMATION 时间戳易被用户态工具修改，而 $FILE_NAME 时间戳仅由 NTFS 驱动（内核态）更新。当 SI 时间戳**早于** FN 时间戳时，很可能存在时间戳篡改：```python
import pandas as pd
from datetime import datetime, timedelta

def load_mft_data(csv_path):
    """Load MFTECmd parsed CSV output."""
    df = pd.read_csv(csv_path, low_memory=False)

    # Parse timestamp columns
    timestamp_cols = [
        "Created0x10", "LastModified0x10", "LastAccess0x10", "LastRecordChange0x10",
        "Created0x30", "LastModified0x30", "LastAccess0x30", "LastRecordChange0x30"
    ]

    for col in timestamp_cols:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors="coerce")

    return df

def detect_timestomping(df):
    """Detect timestamp manipulation by comparing SI and FN attributes.

    Key indicators:
    1. SI Created < FN Created (SI timestamp pushed back in time)
    2. SI timestamps have nanoseconds = 0000000 (tool artifact)
    3. SI Created < FN Entry Modified (impossible under normal NTFS behavior)
    4. Large gap between SI and FN timestamps
    """
    results = []

    for idx, row in df.iterrows():
        si_created = row.get("Created0x10")
        fn_created = row.get("Created0x30")
        si_modified = row.get("LastModified0x10")
        fn_modified = row.get("LastModified0x30")
        si_entry = row.get("LastRecordChange0x10")
        fn_entry = row.get("LastRecordChange0x30")

        if pd.isna(si_created) or pd.isna(fn_created):
            continue

        filepath = row.get("FileName", "unknown")
        parent_path = row.get("ParentPath", "")
        full_path = f"{parent_path}\\{filepath}" if parent_path else filepath
        indicators = []

        # Detection 1: SI Created is BEFORE FN Created
        # Under normal NTFS operations, SI Created >= FN Created
        if si_created < fn_created:
            delta = fn_created - si_created
            indicators.append({
                "check": "SI_Created < FN_Created",
                "si_value": str(si_created),
                "fn_value": str(fn_created),
                "delta": str(delta),
                "confidence": "high"
            })

        # Detection 2: SI Modified is BEFORE FN Created
        # A file cannot be modified before it was created
        if pd.notna(si_modified) and si_modified < fn_created:
            indicators.append({
                "check": "SI_Modified < FN_Created",
                "si_value": str(si_modified),
                "fn_value": str(fn_created),
                "confidence": "high"
            })

        # Detection 3: Nanosecond precision check
        # Many timestomping tools set timestamps with zero nanoseconds
        if pd.notna(si_created):
            si_created_str = str(si_created)
            if ".000000" in si_created_str or si_created_str.endswith("00:00:00"):
                # Check if FN has normal nanosecond precision
                fn_str = str(fn_created)
                if ".000000" not in fn_str:
                    indicators.append({
                        "check": "SI_nanoseconds_zeroed",
                        "si_value": si_created_str,
                        "fn_value": fn_str,
                        "confidence": "medium"
                    })

        # Detection 4: Large time gap between SI and FN
        # Normal gap is seconds to minutes, not years
        if abs((si_created - fn_created).days) > 365:
            indicators.append({
                "check": "SI_FN_gap_exceeds_1_year",
                "si_value": str(si_created),
                "fn_value": str(fn_created),
                "delta_days": abs((si_created - fn_created).days),
                "confidence": "high"
            })

        # Detection 5: SI Entry Modified much later than SI Created
        # Indicates the SI attribute was rewritten
        if pd.notna(si_entry) and pd.notna(si_created):
            entry_delta = si_entry - si_created
            if entry_delta.days > 365 * 5:  # Entry modified years after creation
                indicators.append({
                    "check": "SI_entry_modified_years_after_creation",
                    "si_created": str(si_created),
                    "si_entry_modified": str(si_entry),
                    "confidence": "medium"
                })

        if indicators:
            results.append({
                "file_path": full_path,
                "entry_number": row.get("EntryNumber", ""),
                "in_use": row.get("InUse", True),
                "si_created": str(si_created),
                "fn_created": str(fn_created),
                "indicators": indicators,
                "highest_confidence": max(i["confidence"] for i in indicators),
            })

    return results

# Run detection
df = load_mft_data("D:\\Evidence\\Parsed\\mft_parsed.csv")
stomped_files = detect_timestomping(df)

print(f"\nTimestomping Detection Results")
print(f"{'='*60}")
print(f"Total MFT entries analyzed: {len(df)}")
print(f"Suspicious entries found: {len(stomped_files)}")
print()

for entry in sorted(stomped_files, key=lambda x: x["highest_confidence"], reverse=True):
    print(f"[{entry['highest_confidence'].upper()}] {entry['file_path']}")
    print(f"  SI Created: {entry['si_created']}")
    print(f"  FN Created: {entry['fn_created']}")
    for ind in entry["indicators"]:
        print(f"  Check: {ind['check']} (confidence: {ind['confidence']})")
    print()
```###第4步：与USN期刊分析证实

USN 日志记录即使在时间戳之后仍然存在的元数据更改事件：```python
def correlate_with_usn_journal(stomped_files, usn_csv_path):
    """Cross-reference timestomped files with USN Journal entries.

    The USN Journal records a BASIC_INFO_CHANGE reason when timestamps
    are modified, providing corroborating evidence of timestomping.
    """
    usn_df = pd.read_csv(usn_csv_path, low_memory=False)
    usn_df["UpdateTimestamp"] = pd.to_datetime(usn_df["UpdateTimestamp"], errors="coerce")

    corroborated = []
    for entry in stomped_files:
        filename = entry["file_path"].split("\\")[-1]

        # Find USN entries for this file with BASIC_INFO_CHANGE
        usn_matches = usn_df[
            (usn_df["Name"] == filename) &
            (usn_df["UpdateReasons"].str.contains("BASIC_INFO_CHANGE", na=False))
        ]

        if not usn_matches.empty:
            entry["usn_corroboration"] = True
            entry["usn_change_times"] = usn_matches["UpdateTimestamp"].tolist()
            entry["highest_confidence"] = "critical"
            corroborated.append(entry)
            print(f"[CORROBORATED] {filename} - USN Journal confirms "
                  f"BASIC_INFO_CHANGE at {usn_matches['UpdateTimestamp'].iloc[0]}")

    return corroborated

# Parse USN Journal (use MFTECmd or ANJP)
# MFTECmd.exe -f "$J" --csv D:\Evidence\Parsed\ --csvf usn_parsed.csv
```### 第 5 步：借助 ShimCache 与 Amcache 校验时间线```python
def check_shimcache_timeline(stomped_files, shimcache_csv):
    """Validate timestamps against ShimCache (AppCompatCache) entries.

    ShimCache records the last modification time of executables
    independently of NTFS timestamps, providing another corroboration point.
    """
    shim_df = pd.read_csv(shimcache_csv, low_memory=False)
    shim_df["LastModifiedTimeUTC"] = pd.to_datetime(
        shim_df["LastModifiedTimeUTC"], errors="coerce"
    )

    for entry in stomped_files:
        filepath = entry["file_path"]
        shim_match = shim_df[
            shim_df["Path"].str.lower() == filepath.lower()
        ]

        if not shim_match.empty:
            shim_time = shim_match["LastModifiedTimeUTC"].iloc[0]
            si_modified = pd.to_datetime(entry.get("si_created"))

            if pd.notna(shim_time) and pd.notna(si_modified):
                delta = abs((shim_time - si_modified).days)
                if delta > 30:
                    entry["shimcache_mismatch"] = True
                    entry["shimcache_time"] = str(shim_time)
                    print(f"[SHIMCACHE MISMATCH] {filepath}")
                    print(f"  SI timestamp: {si_modified}")
                    print(f"  ShimCache timestamp: {shim_time}")
                    print(f"  Delta: {delta} days")

    return stomped_files
```### 第 6 步：生成时间戳篡改检测报告```python
import json

def generate_report(stomped_files, output_path):
    """Generate a structured JSON report of all timestomping detections."""
    report = {
        "report_title": "Timestomping Detection Analysis",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "mitre_technique": "T1070.006 - Indicator Removal: Timestomp",
        "total_suspicious_files": len(stomped_files),
        "critical_findings": len([f for f in stomped_files if f["highest_confidence"] == "critical"]),
        "high_findings": len([f for f in stomped_files if f["highest_confidence"] == "high"]),
        "medium_findings": len([f for f in stomped_files if f["highest_confidence"] == "medium"]),
        "findings": stomped_files,
    }

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"Report written to {output_path}")
    print(f"  Critical: {report['critical_findings']}")
    print(f"  High: {report['high_findings']}")
    print(f"  Medium: {report['medium_findings']}")

generate_report(stomped_files, "D:\\Evidence\\timestomping_report.json")
```## 验证

- 确认 MFTECmd 能无错误解析 $MFT，并产出 0x10（SI）与 0x30（FN）时间戳列
- 在实验环境中创建测试文件并用时间戳篡改工具（如 NTimeStomp）验证检测逻辑能捕获篡改
- 验证「纳秒归零」检查不会在安装程序合法设置时间戳的文件上产生过多误报
- 将标记文件与 USN 日志交叉比对，确认在预期时间存在 BASIC_INFO_CHANGE 事件
- 验证 ShimCache 与 Amcache 时间戳能独立佐证时间线不一致
- 在已知洁净的系统镜像上测试以建立误报基线（部分备份/镜像软件会合法重置时间戳）
- 确认检测流水线正确处理已删除 MFT 项（InUse=false），其中可能保留已删恶意文件的时间戳篡改证据