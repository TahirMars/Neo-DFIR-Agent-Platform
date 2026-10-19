---
id: analyzing-windows-registry-for-artifacts
name: analyzing-windows-registry-for-artifacts
name_zh: 分析·Windows·注册表·取证痕迹
description: 提取并分析 Windows 注册表配置单元，以发现用户活动、已安装的软件、自动启动条目以及系统受损的证据。
domain: cybersecurity
subdomain: digital-forensics
tags:
- forensics
- windows-registry
- artifact-analysis
- regripper
- registry-explorer
- evidence-collection
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 分析 Windows 注册表取证痕迹

## 使用时机
- 在事件期间调查 Windows 系统上的用户活动时
- 用于识别恶意软件使用的自动运行/持久性机制
- 跟踪已安装的软件、USB 设备和网络连接时
- 在内部威胁调查期间重建用户操作
- 用于将注册表时间戳与其他取证工件关联起来

## 前置条件
- 取证图像或提取的注册表配置单元文件
- RegRipper、注册表浏览器 (Eric Zimmerman) 或 python-registry
- 访问注册表配置单元位置（SAM、SYSTEM、SOFTWARE、NTUSER.DAT、UsrClass.dat）
- 了解 Windows 注册表结构（配置单元、键、值）
- SIFT 工作站或取证分析环境

## 工作流程
### 第 1 步：从取证图像中提取注册表配置单元

```bash
# Mount the forensic image read-only
mkdir /mnt/evidence
mount -o ro,loop,offset=$((2048*512)) /cases/case-2024-001/images/evidence.dd /mnt/evidence

# Copy system registry hives
cp /mnt/evidence/Windows/System32/config/SAM /cases/case-2024-001/registry/
cp /mnt/evidence/Windows/System32/config/SYSTEM /cases/case-2024-001/registry/
cp /mnt/evidence/Windows/System32/config/SOFTWARE /cases/case-2024-001/registry/
cp /mnt/evidence/Windows/System32/config/SECURITY /cases/case-2024-001/registry/
cp /mnt/evidence/Windows/System32/config/DEFAULT /cases/case-2024-001/registry/

# Copy user-specific hives
cp /mnt/evidence/Users/*/NTUSER.DAT /cases/case-2024-001/registry/
cp /mnt/evidence/Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat /cases/case-2024-001/registry/

# Copy transaction logs (for dirty hive recovery)
cp /mnt/evidence/Windows/System32/config/*.LOG* /cases/case-2024-001/registry/logs/

# Hash all extracted hives
sha256sum /cases/case-2024-001/registry/* > /cases/case-2024-001/registry/hive_hashes.txt
```### 第 2 步：使用 RegRipper 进行分析以实现自动工件提取```bash
# Install RegRipper
git clone https://github.com/keydet89/RegRipper3.0.git /opt/regripper

# Run RegRipper against NTUSER.DAT (user profile)
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/NTUSER.DAT \
   -f ntuser > /cases/case-2024-001/analysis/ntuser_report.txt

# Run against SYSTEM hive
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SYSTEM \
   -f system > /cases/case-2024-001/analysis/system_report.txt

# Run against SOFTWARE hive
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SOFTWARE \
   -f software > /cases/case-2024-001/analysis/software_report.txt

# Run against SAM hive (user accounts)
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SAM \
   -f sam > /cases/case-2024-001/analysis/sam_report.txt

# Run specific plugins
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/NTUSER.DAT \
   -p userassist > /cases/case-2024-001/analysis/userassist.txt

perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SYSTEM \
   -p usbstor > /cases/case-2024-001/analysis/usbstor.txt
```### 第 3 步：Extract Persistence and Autorun Entries```bash
# Using python-registry for targeted extraction
pip install python-registry

python3 << 'PYEOF'
from Registry import Registry

# Open SOFTWARE hive
reg = Registry.Registry("/cases/case-2024-001/registry/SOFTWARE")

# Check Run keys (autostart)
autorun_paths = [
    "Microsoft\\Windows\\CurrentVersion\\Run",
    "Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Microsoft\\Windows\\CurrentVersion\\RunServices",
    "Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"
]

for path in autorun_paths:
    try:
        key = reg.open(path)
        print(f"\n=== {path} (Last Modified: {key.timestamp()}) ===")
        for value in key.values():
            print(f"  {value.name()}: {value.value()}")
    except Registry.RegistryKeyNotFoundException:
        pass

# Check installed services
key = reg.open("Microsoft\\Windows NT\\CurrentVersion\\Svchost")
print(f"\n=== Svchost Groups ===")
for value in key.values():
    print(f"  {value.name()}: {value.value()}")
PYEOF

# Check NTUSER.DAT for user-specific autorun
python3 << 'PYEOF'
from Registry import Registry

reg = Registry.Registry("/cases/case-2024-001/registry/NTUSER.DAT")

user_autorun = [
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run"
]

for path in user_autorun:
    try:
        key = reg.open(path)
        print(f"\n=== {path} (Last Modified: {key.timestamp()}) ===")
        for value in key.values():
            print(f"  {value.name()}: {value.value()}")
    except Registry.RegistryKeyNotFoundException:
        pass
PYEOF
```### 第 4 步：分析用户活动工件```bash
# Extract UserAssist data (program execution history with ROT13 encoding)
python3 << 'PYEOF'
from Registry import Registry
import codecs, struct, datetime

reg = Registry.Registry("/cases/case-2024-001/registry/NTUSER.DAT")

ua_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"
key = reg.open(ua_path)

for guid_key in key.subkeys():
    count_key = guid_key.subkey("Count")
    print(f"\n=== {guid_key.name()} ===")
    for value in count_key.values():
        decoded_name = codecs.decode(value.name(), 'rot_13')
        data = value.value()
        if len(data) >= 16:
            run_count = struct.unpack('<I', data[4:8])[0]
            focus_count = struct.unpack('<I', data[8:12])[0]
            timestamp = struct.unpack('<Q', data[60:68])[0] if len(data) >= 68 else 0
            if timestamp > 0:
                ts = datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=timestamp//10)
                print(f"  {decoded_name}: Runs={run_count}, Focus={focus_count}, Last={ts}")
            else:
                print(f"  {decoded_name}: Runs={run_count}, Focus={focus_count}")
PYEOF

# Extract Recent Documents (MRU lists)
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/NTUSER.DAT \
   -p recentdocs > /cases/case-2024-001/analysis/recentdocs.txt

# Extract typed URLs (browser)
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/NTUSER.DAT \
   -p typedurls > /cases/case-2024-001/analysis/typedurls.txt

# Extract typed paths in Explorer
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/NTUSER.DAT \
   -p typedpaths > /cases/case-2024-001/analysis/typedpaths.txt
```### 第 5 步：Extract System and Network Information```bash
# Computer name and OS version from SYSTEM hive
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SYSTEM \
   -p compname > /cases/case-2024-001/analysis/system_info.txt

# Network interfaces and configuration
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SYSTEM \
   -p nic2 >> /cases/case-2024-001/analysis/system_info.txt

# Wireless network history
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SOFTWARE \
   -p networklist > /cases/case-2024-001/analysis/network_history.txt

# Timezone configuration
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SYSTEM \
   -p timezone > /cases/case-2024-001/analysis/timezone.txt

# Shutdown time
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SYSTEM \
   -p shutdown > /cases/case-2024-001/analysis/shutdown.txt

# Installed software from Uninstall keys
perl /opt/regripper/rip.pl -r /cases/case-2024-001/registry/SOFTWARE \
   -p uninstall > /cases/case-2024-001/analysis/installed_software.txt
```## 关键概念

|概念|描述 |
|---------|-------------|
|注册表配置单元 |存储注册表部分的二进制文件（SAM、SYSTEM、SOFTWARE、NTUSER.DAT）|
| MRU（最近使用的）|列出跟踪最近访问的文件、命令和搜索词 |
|用户协助| ROT13 编码的注册表项使用时间戳跟踪程序执行 |
|垫片缓存 |应用程序兼容性缓存记录执行的程序|
| AmCache |详细的执行历史记录，包括可执行文件的 SHA-1 哈希值 |
| BAM/DAM |后台/桌面活动管理器在 Win10+ 中跟踪程序执行 |
|最后写入时间 |注册表项上的时间戳表明它们上次修改的时间
|交易日志 |日志文件允许在不正常关机后恢复注册表状态|

## 工具和系统

|工具|目的|
|------|---------|
|注册Ripper |使用插件架构自动提取注册表工件 |
|注册表浏览器| Eric Zimmerman 用于交互式注册表分析的 GUI 工具 |
| python 注册表 |用于程序化注册表配置单元解析的 Python 库 |
| RECmd | Eric Zimmerman 命令行注册表分析工具 |
|亚普|另一种用于基于 Python 分析的注册表解析器 |
|应用程序兼容性缓存解析器 |专用 ShimCache/AppCompatCache 解析器 |
| Amcache解析器|专用AmCache.hve分析工具|
| ShellBags 浏览器 |用于分析 ShellBag 工件的专用工具 |

## 常见场景

**场景 1：恶意软件持久性调查**
提取 SOFTWARE 和 NTUSER.DAT 配置单元，检查所有 Run/RunOnce 密钥是否有未经授权的条目，检查服务是否存在可疑添加，检查计划任务注册表项，将自动运行时间戳与恶意软件执行时间线关联起来。

**场景2：用户活动重构**
分析 UserAssist 以获取程序执行历史记录，检查最近文档以获取访问的文件，检查 TypedPaths 以获取资源管理器导航，提取 ShellBags 以获取文件夹访问模式，围绕事件窗口构建用户活动的时间线。

**场景3：未经授权的软件检测**
解析所有已安装应用程序的卸载密钥，与批准的软件基线进行比较，检查 BAM/DAM 是否有最近执行的程序不在批准列表中，即使在卸载后也检查 AppCompatCache 的执行证据。

**场景 4：USB 数据泄露调查**
从 SYSTEM 配置单元中提取已连接设备的 USBSTOR 条目，将设备序列号与 MountedDevices 相关联，检查 NTUSER.DAT MountPoints2 以了解用户对可移动媒体的访问，检查 SetupAPI 日志以获取首次连接时间戳。

## 输出格式

```
Registry Analysis Summary:
  System: DESKTOP-ABC123 (Windows 10 Pro Build 19041)
  Timezone: Eastern Standard Time (UTC-5)
  Last Shutdown: 2024-01-18 23:45:12 UTC

  Autorun Entries:
    HKLM Run:     5 entries (1 suspicious: "updater.exe" -> C:\ProgramData\svc\updater.exe)
    HKCU Run:     3 entries (all legitimate)
    Services:     142 entries (2 unknown: "WinDefSvc", "SysMonAgent")

  User Activity (NTUSER.DAT):
    UserAssist Programs:  234 entries
    Recent Documents:     89 entries
    Typed URLs:           45 entries
    Typed Paths:          12 entries

  USB Devices Connected:
    - Kingston DataTraveler (Serial: 0019E06B4521) - First: 2024-01-10, Last: 2024-01-18
    - WD My Passport (Serial: 575834314131) - First: 2024-01-15, Last: 2024-01-15

  Installed Software:     127 applications
  Suspicious Findings:    3 items flagged for review
```