---
id: analyzing-uefi-bootkit-persistence
name: analyzing-uefi-bootkit-persistence
name_zh: 分析·UEFI·Bootkit·持久化
description: 分析 UEFI 引导套件的持久化机制，包括 SPI 闪存固件植入、EFI 系统分区（ESP）修改、安全启动绕过技术及 UEFI 变量操作。覆盖
  BlackLotus、LoJax、MosaicRegressor、MoonBounce、CosmicStrand 等已知引导套件的检测，执行 ESP 分区取证分析、基于
  Chipsec 的固件完整性校验和安全启动配置审查。处理涉及 UEFI 恶意软件分析、固件持久化调查、启动链完整性验证或安全启动规避检测的请求。
domain: cybersecurity
subdomain: firmware-security
tags:
- UEFI
- bootkit
- firmware
- Secure-Boot
- chipsec
- ESP
- persistence
version: 1.0.0
author: mukul975
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 分析·UEFI·Bootkit·持久化

## 使用时机
- 重新安装操作系统或更换磁盘后，受损系统重新建立 C2 通信
- 安全启动已被篡改、禁用或显示意外的机器所有者密钥 (MOK) 注册
- 固件完整性验证未根据供应商提供的基准进行验证
- 内存取证显示 rootkit 组件在早期启动阶段加载
- 调查已知部署 UEFI 植入的高级持续威胁 (APT) 活动
- 审核企业端点强化的固件安全状况

**请勿在没有 UEFI 的传统 BIOS 系统上使用**基于标准 MBR 的引导套件；请改用 MBR/VBR bootkit 分析。

## 前置条件
- 用于SPI闪存转储、UEFI变量检查和固件安全模块的chipsec框架
- UEFITool / UEFIExtract 用于固件卷解析和 DXE 驱动程序提取
- Python 3.8+，带有 struct、hashlib、subprocess 和 os 模块
- 可启动的 Linux live USB 用于离线分析（避免运行受损的操作系统）
- Volatility 3 用于启动阶段工件的内存取证
- YARA 具有 UEFI 恶意软件规则集，用于基于模式的检测
- 访问供应商固件基线以进行完整性比较

## 工作流程
### 第1步：转储SPI Flash固件

从SPI flash芯片获取UEFI固件进行离线分析：```bash
# Using chipsec to dump SPI flash contents
python chipsec_util.py spi dump firmware_dump.rom

# Using flashrom as an alternative
flashrom -p internal -r firmware_dump.rom

# Verify dump integrity
sha256sum firmware_dump.rom

# Read SPI flash descriptor information
python chipsec_util.py spi info

# Check SPI flash region access permissions
python chipsec_main.py -m common.spi_access

# Verify BIOS write protection is enabled
python chipsec_main.py -m common.bios_wp

# Check SPI flash controller lock
python chipsec_main.py -m common.spi_lock
```### 第2步：检查UEFI变量

枚举并分析 UEFI 变量是否存在未经授权的修改：```bash
# List all UEFI variables on a live system
python chipsec_util.py uefi var-list

# List UEFI variables from a SPI flash dump
python chipsec_util.py uefi var-list-spi firmware_dump.rom

# Read specific Secure Boot variables
python chipsec_util.py uefi var-read SecureBoot 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
python chipsec_util.py uefi var-read SetupMode 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
python chipsec_util.py uefi var-read PK 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
python chipsec_util.py uefi var-read KEK 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
python chipsec_util.py uefi var-read db D719B2CB-3D3A-4596-A3BC-DAD00E67656F

# Dump UEFI key databases for analysis
python chipsec_util.py uefi keys

# Check Secure Boot configuration module
python chipsec_main.py -m common.secureboot.variables
```### 第3步：分析EFI系统分区（ESP）

检查 ESP 是否有未经授权或修改的引导组件：```bash
# Mount ESP (typically the first FAT32 partition, ~100-500MB)
mkdir /mnt/esp
mount /dev/sda1 /mnt/esp

# List all files on ESP with timestamps
find /mnt/esp -type f -exec ls -la {} \;

# Check for BlackLotus indicators - custom directory under ESP:/system32/
ls -la /mnt/esp/system32/ 2>/dev/null

# Verify Windows Boot Manager signature
sigcheck -a /mnt/esp/EFI/Microsoft/Boot/bootmgfw.efi

# Hash all EFI binaries for comparison against known-good values
find /mnt/esp -name "*.efi" -exec sha256sum {} \;

# Check for unauthorized .efi files outside standard directories
find /mnt/esp -name "*.efi" | grep -v "Microsoft\|Boot\|ubuntu\|grub"

# Look for grubx64.efi planted by BlackLotus
find /mnt/esp -name "grubx64.efi" -exec sha256sum {} \;

# Examine MeasuredBoot logs for anomalies (Windows)
# Logs located at C:\Windows\Logs\MeasuredBoot\
```### 第 4 步：扫描固件以查找已知的 Bootkit 签名

分析固件转储中已知的 UEFI 恶意软件模式：```bash
# Extract all firmware modules with UEFIExtract
UEFIExtract firmware_dump.rom all

# Generate firmware module whitelist from vendor baseline
python chipsec_main.py -m tools.uefi.whitelist -a generate,baseline.json,firmware_vendor.rom

# Compare current firmware against whitelist
python chipsec_main.py -m tools.uefi.whitelist -a check,baseline.json,firmware_dump.rom

# Scan firmware with UEFI-specific YARA rules
yara -r uefi_bootkits.yar firmware_dump.rom

# Scan extracted modules individually
find firmware_dump.rom.dump -name "*.efi" -exec yara -r uefi_bootkits.yar {} \;

# Check for modified CORE_DXE module (targeted by MoonBounce, CosmicStrand)
# Compare GUID and hash against vendor baseline
```### 第5步：检测安全启动绕过机制

检查已知的安全启动绕过技术：```bash
# Check if Secure Boot is enabled
python chipsec_main.py -m common.secureboot.variables

# Verify SMM (System Management Mode) protections
python chipsec_main.py -m common.smm

# Check SMM BIOS write protection
python chipsec_main.py -m common.bios_smi

# On Windows - check boot configuration for bypass indicators
bcdedit /enum firmware
bcdedit /v

# Check for testsigning/nointegritychecks/debug flags
bcdedit | findstr /i "testsigning nointegritychecks debug"

# Verify HVCI (Hypervisor-enforced Code Integrity) is not disabled
# BlackLotus sets HKLM:\...\DeviceGuard\...\HypervisorEnforcedCodeIntegrity Enabled=0
reg query "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled

# Check Secure Boot state via PowerShell
# Confirm-SecureBootUEFI returns True if properly enabled
```###第6步：执行引导链完整性验证

验证引导链中从固件到内核的每个组件：```bash
# Verify firmware integrity against vendor hash
sha256sum firmware_dump.rom
# Compare with vendor-published hash

# Verify bootloader signatures
sigcheck -a C:\Windows\Boot\EFI\bootmgfw.efi
sigcheck -a C:\Windows\System32\winload.efi
sigcheck -a C:\Windows\System32\ntoskrnl.exe

# Check for unsigned or invalid boot drivers
sigcheck -u -e C:\Windows\System32\drivers\

# Analyze Measured Boot logs for unexpected EFI_Boot_Services_Application entries
# BlackLotus components appear as EV_EFI_Boot_Services_Application

# Memory forensics for boot-phase artifacts
vol3 -f memory.dmp windows.modules
vol3 -f memory.dmp windows.driverscan
```### 第 7 步：记录 UEFI Bootkit 分析结果

编制综合分析报告：```
Report should include:
- Firmware version, vendor, and platform identification
- SPI flash protection status (write protect, lock bits, access control)
- Secure Boot configuration and any bypass indicators detected
- UEFI variable anomalies (unauthorized keys, modified db/dbx, MOK enrollment)
- ESP contents inventory with hash verification against known-good baselines
- Firmware module comparison against vendor whitelist (added, modified, removed)
- Known bootkit family attribution with confidence level
- Boot chain integrity verification results for each component
- Remediation steps (reflash, key rotation, hardware replacement)
- MITRE ATT&CK mapping (T1542.001 - System Firmware, T1542.003 - Bootkit)
```## 关键概念

|术语 |定义|
|------|------------|
| **UEFI 启动套件** |恶意软件持续存在于 UEFI 固件或启动过程中，在操作系统加载之前执行，并且在操作系统重新安装后仍然存在 |
| **SPI 闪存** |主板上的串行外设接口闪存芯片存储UEFI固件； LoJax 和 MoonBounce 等固件级 bootkit 会修改 SPI 闪存内容
| **EFI 系统分区 (ESP)** |包含 EFI 引导加载程序和驱动程序的 FAT32 分区；像 BlackLotus 和 ESPecter 这样的 bootkit 会修改 ESP 上的文件以实现持久性 |
| **安全启动** | UEFI安全功能，可验证启动组件的数字签名；可以通过漏洞 (CVE-2022-21894) 或 MOK 注册绕过 |
| **DXE 驱动程序** | UEFI启动期间加载的驱动程序执行环境驱动程序；固件植入会注入在操作系统之前执行的恶意 DXE 驱动程序
| **机器所有者密钥 (MOK)** |用户可安装的安全启动密钥； BlackLotus 注册攻击者控制的 MOK 来签署恶意引导加载程序 |
| **芯片安全** |用于分析 SPI 闪存、UEFI 变量、安全启动和硬件安全配置的英特尔平台安全评估框架 |
| **HVCI** |管理程序强制执行的代码完整性是一项 Windows 安全功能，bootkit 禁止加载未签名的内核驱动程序 |

## 工具和系统

- **chipsec**：用于转储 SPI 闪存、读取 UEFI 变量、验证固件写保护和安全启动配置审核的英特尔框架
- **UEFITool**：开源 UEFI 固件映像解析器，用于检查固件卷、提取 DXE 驱动程序和比较模块 GUID
- **sigcheck**：Sysinternals 实用程序，用于验证 EFI 二进制文件和引导链组件的数字签名
- **flashrom**：开源 SPI 闪存编程器，用于在支持的平台上读写固件芯片
- **YARA**：与 UEFI 特定规则集一起使用的模式匹配引擎，用于检测固件转储中的已知 bootkit 签名

## 常见场景

### 场景：调查持续存在的操作系统重新安装的危害

**背景**：在确认违规后，企业端点被重新镜像，但相同的 C2 信标在数小时内恢复。该端点具有启用安全启动的 UEFI 固件和 TPM 2.0 芯片。安全团队怀疑存在类似于 BlackLotus 或 LoJax 的 UEFI 级植入。

**方法**：
1. 从受信任的 Linux live USB 启动系统，以避免执行任何受损的操作系统组件
2.使用“chipsec_util.py spi dump”转储SPI闪存固件以进行离线分析
3. 挂载 ESP 并对所有“.efi”文件进行哈希处理，以便与相同硬件中的已知良好值进行比较
4. 检查 `ESP:/system32/` 目录（BlackLotus 指示器）和未经授权的 `grubx64.efi`
5. 使用 UEFIExtract 提取固件模块并将 GUID 库存与供应商基线进行比较
6. 验证安全启动变量 - 查找未经授权的 MOK 注册或修改的 db/dbx
7. 使用chipsec模块检查SPI闪存写保护和锁定位
8. 使用 UEFI 特定的 YARA 规则扫描固件转储和提取的模块
9. 如果怀疑 BlackLotus，请检查注册表中是否有 HVCI 已禁用以及 MeasuredBoot 日志中是否有异常条目

**陷阱**：
- 从受感染的操作系统运行分析（rootkit 组件隐藏在实时分析中）
- 仅检查 ESP，而不检查 SPI 闪存固件（错过了 LoJax、MoonBounce 等固件级植入）
- 假设安全启动阻止所有启动套件（CVE-2022-21894 和其他绕过存在）
- 修复前不保留原始固件转储（关键取证证据）
- 在不验证供应商映像是否真实且未经修改的情况下重新刷新固件

## 输出格式```
UEFI BOOTKIT PERSISTENCE ANALYSIS REPORT
============================================
System:           Lenovo ThinkPad X1 Carbon Gen 11
Firmware:         N3HET82W (1.54) - Lenovo UEFI BIOS
Platform:         Intel 13th Gen (Raptor Lake)
TPM:              2.0 (Infineon SLB 9672)
Secure Boot:      ENABLED (BYPASSED via CVE-2022-21894)
Analysis Method:  Linux live USB + chipsec + UEFITool

SPI FLASH PROTECTION STATUS
BIOS Write Protection:    DISABLED [!]
SPI Flash Lock (FLOCKDN): SET [OK]
SMM BIOS Write Protect:   DISABLED [!]
SPI Protected Ranges:     Region 0 only (descriptor)

UEFI VARIABLE ANALYSIS
SecureBoot:        Enabled (value=1)
SetupMode:         Disabled (value=0)
PK:                Lenovo Ltd. (legitimate)
KEK:               Microsoft + Lenovo (legitimate)
db:                MODIFIED - contains unauthorized entry [!]
  [!] Unknown certificate: CN=Secure Boot Signing, O=Unknown
  [!] Not present in vendor baseline db
MOK:               1 unauthorized key enrolled [!]
  [!] MOK enrolled: CN=shim, self-signed, not from distro vendor

ESP PARTITION ANALYSIS
Total EFI binaries:     12
Verified (signed):      9
Modified (hash mismatch): 2 [!]
Unauthorized:           1 [!]

  [!] EFI/Microsoft/Boot/bootmgfw.efi - MODIFIED
      Expected SHA-256: a3f2c8...
      Current SHA-256:  7b1e4d...
      Signature:        Valid (signed with unauthorized MOK)

  [!] EFI/Microsoft/Boot/grubx64.efi - UNAUTHORIZED
      SHA-256:  e9c1a7...
      Not present in vendor baseline
      Matches BlackLotus stage-2 loader signature

  [!] system32/ directory present on ESP (BlackLotus artifact)
      Directory empty (files deleted post-installation)

FIRMWARE MODULE ANALYSIS
Total firmware modules:   312
Vendor baseline modules:  312
Added modules:            0
Modified modules:         0
SPI flash integrity:      CLEAN (no firmware-level implant detected)

BOOTKIT ATTRIBUTION
Family:           BlackLotus
Confidence:       HIGH
Persistence:      ESP-based (not SPI flash)
Bypass Method:    CVE-2022-21894 (baton drop)
MITRE ATT&CK:    T1542.003 (Bootkit), T1553.006 (Code Signing Policy Modification)

INDICATORS OF COMPROMISE
- ESP:/system32/ directory (empty, post-cleanup artifact)
- ESP:/EFI/Microsoft/Boot/grubx64.efi (unauthorized, BlackLotus loader)
- Modified bootmgfw.efi (re-signed with attacker MOK)
- HVCI disabled via registry: DeviceGuard\...\Enabled = 0
- Unauthorized MOK enrollment in UEFI variable store
- MeasuredBoot log shows EV_EFI_Boot_Services_Application for grubx64.efi

REMEDIATION
1. Replace bootmgfw.efi with authentic copy from Windows installation media
2. Delete unauthorized grubx64.efi and system32/ directory from ESP
3. Reset Secure Boot keys to factory defaults (clear MOK, restore PK/KEK/db)
4. Enable BIOS write protection and verify SPI flash lock bits
5. Apply firmware update to latest version (patches CVE-2022-21894)
6. Enable HVCI and verify via Group Policy
7. Reimport only trusted certificates into Secure Boot db
8. Monitor MeasuredBoot logs for anomalous boot component loading
```