---
id: analyzing-windows-prefetch-with-python
name: analyzing-windows-prefetch-with-python
name_zh: 分析·Windows·Prefetch·Python
description: 本技能「分析·Windows·Prefetch·Python」（标识 analyzing-windows-prefetch-with-python）面向网络安全检测、分析与响应场景；操作步骤、命令与脚本见正文及
  scripts/、references/ 目录。涉及第三方 API、CLI 与产品名称处保留英文。请在授权与组织策略允许范围内使用。
domain: cybersecurity
subdomain: digital-forensics
tags:
- digital-forensics
- windows
- prefetch
- execution-history
- incident-response
- malware-analysis
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 分析·Windows·Prefetch·Python

## 概述
Windows 预取文件 (.pf) 记录应用程序执行数据，包括可执行文件名称、运行计数、时间戳、加载的 DLL 和访问的目录。该技能涵盖使用 windowsprefetch Python 库解析预取文件以重建执行时间线，通过将可执行文件名称与加载的资源进行比较来检测重命名或伪装的二进制文件，以及识别可能表明恶意软件执行或横向移动的可疑程序。


## 使用时机
- 在调查需要使用 Python 分析 Windows 预取的安全事件时
- 为该域构建检测规则或威胁搜寻查询时
- 当 SOC 分析师需要这种分析类型的结构化程序时
- 验证相关攻击技术的安全监控覆盖范围时

## 前置条件
- Python 3.9+ 带有 `windowsprefetch` 库 (pip install windowsprefetch)
- Windows 从 C:\Windows\Prefetch\ 目录获取预取文件（支持版本 17-30）
- 了解 Windows 预取文件命名约定 (EXECUTABLE-HASH.pf)

## 步骤

### 第1步：收集预取文件
从目标系统的 C:\Windows\Prefetch\ 目录收集 .pf 文件。

### 第2步：解析执行历史
提取可执行文件名称、运行计数、上次执行时间戳和卷信息。

### 第3步：检测可疑执行
标记已知的攻击工具（mimikatz、psexec 等）、重命名的二进制文件以及异常的执行模式。

### 第4步：构建执行时间线
从所有预取文件重建按时间顺序执行的时间线。

## 预期输出

JSON 报告，包含执行历史记录、可疑可执行文件、重命名的二进制指示器和时间线重建。

## 输出示例

```json
{
  "executions": [
    {
      "executable": "notepad.exe",
      "run_count": 42,
      "last_run": "2023-09-15T14:32:17.000000Z",
      "volume_info": "C: (NTFS) 0x1234567890abcdef"
    }
  ],
  "suspicious": [
    {
      "name": "svchost.exe",
      "hash_mismatch": true,
      "expected_hash": "a1b2c3d4e5f678901234567890abcdef1234567890",
      "actual_hash": "0123456789abcdef1234567890abcdef1234567890"
    }
  ],
  "timeline": [
    {
      "timestamp": "2023-09-15T14:32:17.000000Z",
      "event": "notepad.exe executed from C:\\Windows\\System32\\"
    },
    {
      "timestamp": "2023-09-15T14:33:01.000000Z",
      "event": "cmd.exe executed from C:\\Users\\Administrator\\"
    }
  ]
}
``````text
$ python3 prefetch_analyzer.py --dir /evidence/Windows/Prefetch --output /analysis/prefetch_report

Windows Prefetch Analyzer v2.1
================================
Source: /evidence/Windows/Prefetch/
Prefetch Format: Windows 10 (MAM compressed, version 30)
Files Found: 234

--- Execution Timeline (Incident Window: 2024-01-15 to 2024-01-18) ---
Last Executed (UTC)     | Run Count | Filename                    | Hash     | Path
------------------------|-----------|-----------------------------|----------|------------------------------------------
2024-01-15 14:33:15     | 1         | Q4_REPORT.XLSM-2A1B3C4D.pf | 2A1B3C4D | C:\Users\jsmith\Downloads\Q4_Report.xlsm
2024-01-15 14:35:44     | 1         | POWERSHELL.EXE-A2B3C4D5.pf  | A2B3C4D5 | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
2024-01-15 14:36:30     | 3         | UPDATE_CLIENT.EXE-B3C4D5E6.pf| B3C4D5E6| C:\ProgramData\Updates\update_client.exe
2024-01-15 15:10:22     | 1         | NETSCAN.EXE-C4D5E6F7.pf     | C4D5E6F7 | C:\Users\jsmith\Downloads\netscan.exe
2024-01-16 02:28:00     | 1         | PROCDUMP64.EXE-D5E6F7A8.pf  | D5E6F7A8 | C:\Windows\Temp\procdump64.exe
2024-01-16 02:30:15     | 2         | MIMIKATZ.EXE-E6F7A8B9.pf    | E6F7A8B9 | C:\Windows\Temp\mimikatz.exe
2024-01-16 02:40:00     | 4         | PSEXEC.EXE-F7A8B9C0.pf      | F7A8B9C0 | C:\Users\jsmith\AppData\Local\Temp\psexec.exe
2024-01-17 02:45:00     | 1         | SDELETE64.EXE-A8B9C0D1.pf   | A8B9C0D1 | C:\Windows\Temp\sdelete64.exe
2024-01-18 03:00:45     | 1         | WEVTUTIL.EXE-B9C0D1E2.pf    | B9C0D1E2 | C:\Windows\System32\wevtutil.exe

--- Renamed Binary Detection ---
ALERT: UPDATE_CLIENT.EXE 加载的 DLL 与 Cobalt Strike beacon 一致：
  引用的 DLL：wininet.dll, ws2_32.dll, advapi32.dll, dnsapi.dll, netapi32.dll
  卷：\VOLUME{01d94f2a3b5c7d8e-A4E73F21} (C:)
  引用的目录：
    C:\ProgramData\Updates\
    C:\Windows\System32\

--- Execution Frequency Analysis ---
最频繁执行（前5名）：
  1. SVCHOST.EXE          (267 次运行)
  2. CHROME.EXE           (189 次运行)
  3. EXPLORER.EXE         (156 次运行)
  4. RUNTIMEBROKER.EXE    (134 次运行)
  5. OUTLOOK.EXE          (98 次运行)

首次执行（在事件窗口前从未见过）：
  6 个可执行文件在 2024-01-15 到 2024-01-18 期间首次运行

摘要：
  总预取文件数：         234
  可疑可执行文件数：       6
  重命名二进制指示器数：    1 (update_client.exe)
  反取证工具数：          2 (sdelete64.exe, wevtutil.exe)
  JSON 报告： /analysis/prefetch_report/prefetch_timeline.json
```