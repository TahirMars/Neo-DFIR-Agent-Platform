---
id: analyzing-windows-amcache-artifacts
name: analyzing-windows-amcache-artifacts
name_zh: 分析·Windows·Amcache·取证痕迹
description: 解析和分析 Windows Amcache.hve 注册表配置单元，以提取程序执行、应用程序安装和驱动程序加载的证据，以进行数字取证调查。使用
  Eric Zimmerman 的 AmcacheParser 和 Timeline Explorer 进行工件提取、SHA-1 哈希与威胁情报的关联以及时间线重建。激活涉及
  Amcache 取证、程序执行证据、Windows 工件分析或应用程序兼容性缓存调查的请求。
domain: cybersecurity
subdomain: digital-forensics
tags:
- amcache
- windows-forensics
- program-execution
- AmcacheParser
- eric-zimmerman
- timeline-analysis
- DFIR
version: 1.0.0
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 分析·Windows·Amcache·取证痕迹

## 使用时机
- 确定事件响应期间 Windows 系统上存在或执行的程序
- 将 Amcache 中的 SHA-1 哈希与已知恶意软件数据库（VirusTotal、CIRCL、MISP）相关联
- 为取证调查建立应用程序安装和执行时间表
- 识别已删除的可执行文件，即使在文件删除后也会在 Amcache 中留下痕迹
- 通过记录哪些便携式或未经授权的应用程序来调查内部威胁
- 分析驱动程序加载历史记录以检测 Rootkit 或恶意内核模块

**请勿使用**作为程序执行的唯一证明。 Amcache证明文件存在和元数据注册，但ShimCache（AppCompatCache）和Prefetch提供更强的执行证据。一起使用所有三个工件进行结论性分析。

## 前置条件
- “C:\Windows\appcompat\Programs\Amcache.hve”的取证图像或实时分类副本（以及关联的“.LOG1”、“.LOG2”事务日志）
- Eric Zimmerman 的 AmcacheParser (`AmcacheParser.exe`) 从 https://ericzimmerman.github.io/ 下载
- Eric Zimmerman 的时间线资源管理器，用于查看解析的 CSV 输出
- 可选：用于手动配置单元检查的注册表浏览器
- 用于过滤的已知良好可执行文件（例如 NSRL 哈希集）的 SHA-1 白名单
- 安装了 .NET 6+ 运行时（当前 EZ 工具需要）
- 对 CSV 结果的输出目录的写访问权限

## 工作流程
### 第1步：获取Amcache.hve文件

从取证图像或实时系统中提取 Amcache 配置单元：```powershell
# From a live system (requires elevated privileges and raw copy tool)
# Amcache.hve is locked by the system; use a raw disk copy tool
# Option A: FTK Imager - mount image and navigate to:
# C:\Windows\appcompat\Programs\Amcache.hve
# Also collect: Amcache.hve.LOG1, Amcache.hve.LOG2

# Option B: Using KAPE for automated triage collection
kape.exe --tsource C: --tdest D:\Evidence\%m --target Amcache

# Option C: From a mounted forensic image (E: = mounted image)
copy "E:\Windows\appcompat\Programs\Amcache.hve" D:\Evidence\
copy "E:\Windows\appcompat\Programs\Amcache.hve.LOG1" D:\Evidence\
copy "E:\Windows\appcompat\Programs\Amcache.hve.LOG2" D:\Evidence\
```始终收集配置单元旁边的事务日志文件（`.LOG1`、`.LOG2`）。 AmcacheParser 重播这些日志中未提交的事务以恢复最完整的数据。

### 第2步：使用AmcacheParser解析Amcache

针对获取的配置单元运行 AmcacheParser：```powershell
# Basic parsing with CSV output
AmcacheParser.exe -f "D:\Evidence\Amcache.hve" --csv "D:\Evidence\Output"

# Parse with a SHA-1 whitelist to exclude known-good entries (NSRL)
AmcacheParser.exe -f "D:\Evidence\Amcache.hve" -w "D:\Whitelists\nsrl_sha1.txt" --csv "D:\Evidence\Output"

# Parse with a SHA-1 inclusion list (only show matches against known-bad hashes)
AmcacheParser.exe -f "D:\Evidence\Amcache.hve" -b "D:\IOCs\malware_sha1.txt" --csv "D:\Evidence\Output"

# Include deleted entries with high-precision timestamps
AmcacheParser.exe -f "D:\Evidence\Amcache.hve" --csv "D:\Evidence\Output" -i --mp
```AmcacheParser 在输出目录中生成多个 CSV 文件：

|输出文件|内容 |
|----------|----------|
| `Amcache_AssociatedFileEntries.csv` |具有 SHA-1 哈希值、路径、大小和时间戳的文件条目 |
| `Amcache_UnlinkedFileEntries.csv` |旧版 Amcache 格式中的孤立文件条目 |
| `Amcache_ProgramEntries.csv` |安装的程序元数据（名称、发布者、版本、安装日期）|
| `Amcache_DeviceContainers.csv` | USB 和设备连接历史记录 |
| `Amcache_DevicePnps.csv` |即插即用设备驱动程序信息 |
| `Amcache_DriverBinaries.csv` |加载带有路径和哈希值的驱动程序二进制文件 |

### 第 3 步：分析文件条目中是否存在可疑程序

在时间线资源管理器中打开“AssociatedFileEntries.csv”并检查关键列：```
Key columns to review:
- ProgramId          : Links file to its parent program entry
- SHA1               : Hash for threat intel lookups
- FullPath           : Original file location on disk
- FileSize           : Size of the executable
- FileKeyLastWriteTimestamp : When the Amcache entry was last updated
- Name               : File name
- Publisher           : Code signing publisher (blank = unsigned)
- BinProductVersion  : Version string from the PE header
- LinkDate           : PE compilation timestamp (useful for detecting timestomping)
```过滤可疑指标：```
# In Timeline Explorer, apply these filters:

# 1. Find unsigned executables (potentially malicious)
Publisher column = (empty)

# 2. Find executables from suspicious paths
FullPath contains: \temp\, \appdata\, \downloads\, \public\, \programdata\

# 3. Find executables with recent timestamps during incident window
FileKeyLastWriteTimestamp between: 2026-03-15 00:00:00 and 2026-03-16 00:00:00

# 4. Find executables with suspicious compilation dates (timestomping)
LinkDate year < 2015 AND FileKeyLastWriteTimestamp year = 2026
```### 第 4 步：将 SHA-1 哈希值与威胁情报关联起来

提取 SHA-1 哈希值并检查恶意软件数据库：```powershell
# Extract unique SHA-1 hashes from the parsed output
# Using PowerShell to extract the SHA1 column
Import-Csv "D:\Evidence\Output\Amcache_AssociatedFileEntries.csv" |
  Select-Object -ExpandProperty SHA1 -Unique |
  Where-Object { $_ -ne "" } |
  Out-File "D:\Evidence\Output\extracted_hashes.txt"

# Check hashes against VirusTotal using vt-cli
foreach ($hash in Get-Content "D:\Evidence\Output\extracted_hashes.txt") {
    vt file $hash --format json | Select-Object -Property meaningful_name, last_analysis_stats
}

# Check hashes against CIRCL hashlookup
foreach ($hash in Get-Content "D:\Evidence\Output\extracted_hashes.txt") {
    Invoke-RestMethod -Uri "https://hashlookup.circl.lu/lookup/sha1/$hash"
}

# Cross-reference with NSRL to identify known-good vs. unknown
# Unknown hashes that are not in NSRL warrant closer investigation
```### 第 5 步：分析程序条目是否存在未经授权的安装

查看“ProgramEntries.csv”以了解攻击者可能安装的软件：```
Key columns in ProgramEntries:
- ProgramName        : Display name of installed application
- ProgramVersion     : Version string
- Publisher          : Software publisher
- InstallDate        : When the program was installed
- Source             : Installation source (msi, exe, etc.)
- UninstallKey       : Registry uninstall path
- PathsList         : Installation directories
```寻找：
- 远程访问工具（AnyDesk、TeamViewer、ngrok、Chisel）
- 黑客工具（Mimikatz、PsExec、Cobalt Strike）
- 隧道实用程序（plink、socat、WireGuard）
- 事件窗口期间安装的程序
- 程序安装到非标准位置

### 第 6 步：分析驱动程序二进制文件以获取 Rootkit 证据

查看“DriverBinaries.csv”以查找可疑加载的驱动程序：```
Key columns in DriverBinaries:
- DriverName         : Name of the driver
- DriverInBox        : Whether it shipped with Windows (false = third-party)
- DriverSigned       : Whether the driver has a valid signature
- DriverTimeStamp    : Compilation timestamp
- Product            : Product associated with the driver
- ProductVersion     : Driver version
- SHA1               : Hash of the driver binary
```筛选“DriverInBox = false”和“DriverSigned = false”以查找未签名的第三方驱动程序，这些驱动程序可能是 BYOVD（自带易受攻击的驱动程序）攻击中使用的 Rootkit 或易受攻击的驱动程序。

### 第 7 步：从 Amcache 数据构建时间线

将 Amcache 数据与其他工件结合起来以获得全面的时间线：```powershell
# Merge Amcache CSV with other EZ Tools output using Timeline Explorer
# Load the following CSVs into Timeline Explorer:
# - Amcache_AssociatedFileEntries.csv (file evidence)
# - Amcache_ProgramEntries.csv (install evidence)
# - Prefetch output from PECmd.exe (execution evidence)
# - ShimCache output from AppCompatCacheParser.exe (execution evidence)

# Sort all entries by timestamp to reconstruct the attack sequence
# Timeline Explorer supports multi-file loading and column-based sorting

# Export the combined timeline
# File > Save to CSV > combined_timeline.csv
```## 关键概念

|术语 |定义|
|------|------------|
| **Amcache.hve** |位于“C:\Windows\appcompat\Programs\Amcache.hve”的 Windows 注册表配置单元，用于存储有关应用程序、文件和驱动程序的元数据，以实现应用程序兼容性 |
| **相关文件条目** |链接到特定程序安装的 Amcache 记录，包含文件路径、大小、哈希值和时间戳 |
| **未关联的文件条目** |未链接到程序条目的旧格式的孤立 Amcache 记录；常见于Windows 7/8系统|
| **节目输入** | Amcache 记录包含安装元数据：程序名称、版本、发布者、安装日期和卸载密钥 |
| **SHA-1 哈希** | Amcache 中存储的每个注册文件的加密哈希值，可通过威胁情报查找来识别恶意软件 |
| **链接日期** |嵌入在可执行文件头中的PE编译时间戳；与文件系统时间戳的差异可能表明时间戳
| **交易日志** |包含未提交的注册表事务的“.LOG1”和“.LOG2”文件，AmcacheParser 会重播这些文件以实现完整的数据恢复 |
| **NSRL（国家软件参考图书馆）** | NIST 维护的已知商业软件的 SHA-1 哈希数据库，用作过滤良性条目的白名单 |

## 验证

- [ ] Amcache.hve 和事务日志（LOG1、LOG2）是从取证图像中收集的
- [ ] AmcacheParser 生成了所有预期的 CSV 输出文件，没有错误
- [ ] 提取 SHA-1 哈希值并根据 VirusTotal 或 CIRCL 哈希查找进行检查
- [ ] 可疑路径中未签名的可执行文件已被标记以供进一步分析
- [ ] 程序条目显示事件窗口内的所有软件安装
- [ ] 已检查驱动程序二进制文件中是否有未签名或开箱即用的条目
- [ ] 已执行 LinkDate 与 FileKeyLastWriteTimestamp 比较以检测时间戳
- [ ] Amcache 发现与 Prefetch 和 ShimCache 相关以进行执行确认
- [ ] 最终时间线将 Amcache 数据与其他取证工件集成