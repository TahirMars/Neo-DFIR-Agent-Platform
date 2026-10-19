---
id: analyzing-windows-shellbag-artifacts
name: analyzing-windows-shellbag-artifacts
name_zh: 分析·Windows·Shellbag·取证痕迹
description: 使用 SBECmd 和 ShellBags Explorer 分析 Windows Shellbag 注册表工件以重建用户文件夹浏览活动，检测可移动媒体和网络共享的访问行为，并追踪已删除目录的用户交互痕迹。
domain: cybersecurity
subdomain: digital-forensics
tags:
- shellbags
- windows-registry
- sbecmd
- shellbags-explorer
- folder-access
- user-activity
- removable-media
- network-shares
- bagmru
- dfir
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 分析·Windows·Shellbag·取证痕迹

## 概述
Shellbag 是 Windows 注册表工件，用于记录用户通过资源管理器与文件夹交互的行为，包括视图设置（如图标大小、窗口位置、排序方式和视图模式）。从取证角度，Shellbags 可提供明确的文件夹访问证据，即使该文件夹已不存在于系统中。当用户通过资源管理器、"打开/保存"对话框或控制面板浏览文件夹时，会在注册表配置单元中创建或更新 Shellbag 条目。这些条目在文件夹删除、驱动器断开连接或用户配置文件重置后仍会保留，因此对于证明用户访问过本地驱动器、USB设备、网络共享或zip压缩包中的特定目录具有重要价值。

## 使用时机
- 安全事件调查需要分析 Windows shellbag 工件时
- 构建该领域的检测规则或威胁搜寻查询时
- SOC 分析师需要结构化分析流程时
- 验证安全监控对相关攻击技术的覆盖范围时

## 注册表位置

### Windows 7/8/10/11

| 蜂巢 | 关键路径 | 存储内容 |
|------|---------|--------|
| NTUSER.DAT | 软件\Microsoft\Windows\Shell\BagMRU | 文件夹层次结构树 |
| NTUSER.DAT | 软件\微软\Windows\Shell\Bags | 每个文件夹的视图设置 |
| UsrClass.dat | 本地设置\软件\Microsoft\Windows\Shell\BagMRU | 桌面/资源管理器外壳 |
| UsrClass.dat | 本地设置\软件\微软\Windows\Shell\Bags | 附加视图设置 |

### BagMRU 结构
BagMRU 密钥包含代表目录结构的编号子密钥的层级树。每个子项值包含 Shell 项 (SHITEMID) 二进制 blob，对文件夹标识进行编码：
- **根 (BagMRU)**：桌面命名空间根
- **BagMRU\0**：通常是"我的电脑"
- **BagMRU\0\0**：第一个驱动器（例如 C:）
- **BagMRU\0\0\0**：C: 上的第一个子文件夹

每个外壳项目包含：
- 项目类型（文件夹、驱动器、网络、zip、控制面板）
- 简称（8.3 格式）
- 长名称（Unicode）
- 创建/修改时间戳
- NTFS 文件夹的 MFT 条目/序列

## 使用 EZ 工具进行分析

### SBECmd（命令行）

```powershell
# 从注册表配置单元目录解析 shellbags
SBECmd.exe -d "C:\Evidence\Registry" --csv C:\Output --csvf shellbags.csv

# 从实时系统解析（需要管理员权限）
SBECmd.exe --live --csv C:\Output --csvf live_shellbags.csv

# 关键输出列：
# AbsolutePath - 完整重建路径
# CreatedOn - 文件夹首次浏览时间
# ModifiedOn - 视图设置最后修改时间
# AccessedOn - 最后访问时间戳
# ShellType - 外壳项目类型（目录、驱动器、网络等）
# Value - 原始外壳项目数据
```

### ShellBags Explorer（GUI）

```powershell
# 启动 GUI 工具进行交互式分析
ShellBagsExplorer.exe

# 加载注册表配置单元：文件 > 加载配置单元
# 浏览树结构查看文件夹层级
# 右键条目查看详细外壳项目属性
```

## 法医调查场景

### 证明 USB 设备浏览

```text
Shellbag 路径: My Computer\E:\Confidential\Project_Files
ShellType: 目录（可移动卷）
CreatedOn: 2025-03-15 09:30:00 UTC

这证明用户通过资源管理器导航到 E:\Confidential\Project_Files
即使 USB 驱动器已断开连接。卷字母 E: 和目录时间戳可与
USBSTOR 和 MountPoints2 注册表条目关联。
```

### 检测网络共享访问

```text
Shellbag 路径: \\FileServer01\Finance\Q4_Reports
ShellType: 网络位置
AccessedOn: 2025-02-20 14:15:00 UTC

这证明用户访问过网络共享，即使该共享已停用或访问权限被撤销。
```

### 识别已删除文件夹知识

```text
Shellbag 路径: C:\Users\suspect\Documents\Exfiltration_Staging
ShellType: 目录
CreatedOn: 2025-01-10 08:00:00 UTC

尽管 C:\Users\suspect\Documents\Exfiltration_Staging 已不存在，
Shellbag 条目仍证明用户创建并访问过该文件夹。
```

## 限制
- Shellbags 仅记录文件夹级别的交互，不记录单个文件访问
- 仅通过资源管理器外壳和打开/保存对话框创建
- 命令行访问（cmd、PowerShell）不会生成 Shellbag 条目
- 通过 API 的编程文件访问不会生成 Shellbag 条目
- 时间戳可能反映视图设置更改，不一定反映实际文件夹访问
- Windows 可能在资源管理器关闭期间批量更新 Shellbag 条目

## 参考资料
- Shellbags 取证分析 2025：https://www.cybertriage.com/blog/shellbags-forensic-analysis-2025/
- SANS Shellbag 取证：https://www.sans.org/blog/computer-forensic-artifacts-windows-7-shellbags
- Magnet Forensics Shellbag 分析：https://www.magnetforensics.com/blog/forensic-analysis-of-windows-shellbags/
- ShellBags Explorer：https://ericzimmerman.github.io/

## 输出示例

```text
$ SBECmd.exe -d "C:\Evidence\Users\jsmith" --csv /analysis/shellbag_output

SBECmd v2.1.0 - ShellBags Explorer (Command Line)
====================================================
Processing hives for user: jsmith
  NTUSER.DAT:  C:\Evidence\Users\jsmith\NTUSER.DAT
  UsrClass.dat: C:\Evidence\Users\jsmith\AppData\Local\Microsoft\Windows\UsrClass.dat

[+] NTUSER.DAT shellbag entries:   456
[+] UsrClass.dat shellbag entries: 1,234
[+] Total shellbag entries:        1,690

--- 文件夹访问时间线（事件窗口） ---
最后访问时间（UTC）     | 文件夹路径                                             | 类型        | 访问次数
------------------------|---------------------------------------------------------|-------------|-------------
2024-01-15 14:34:05     | C:\Users\jsmith\Downloads                               | 文件系统 | 45
2024-01-15 14:36:25     | C:\ProgramData\Updates                                  | 文件系统 | 3
2024-01-15 15:05:00     | \\FILESERV01\Finance                                    | 网络     | 2
2024-01-15 15:12:30     | \\FILESERV01\Finance\Q4_Reports                          | 网络     | 1
2024-01-15 15:30:00     | E:\                                                     | 可移动   | 4
2024-01-15 15:30:45     | E:\Backup                                               | 可移动   | 3
2024-01-15 15:31:20     | E:\Backup\Corporate_Data                                | 可移动   | 2
2024-01-15 16:12:45     | \\FILESERV01\HR\Employees                                | 网络     | 1
2024-01-15 16:15:00     | \\FILESERV01\HR\Employees\Records_2024                   | 网络     | 1
2024-01-16 02:35:00     | C:\Windows\Temp                                         | 文件系统 | 5
2024-01-17 02:44:00     | C:\ProgramData\svc                                     | 文件系统 | 2
2024-01-18 01:10:00     | C:\Users\jsmith\AppData\Local\Temp                      | 文件系统 | 8

--- 网络共享访问 ---
  \\FILESERV01\Finance             首次: 2023-09-10  最后: 2024-01-15
  \\FILESERV01\Finance\Q4_Reports  首次: 2024-01-15  最后: 2024-01-15  (NEW)
  \\FILESERV01\HR\Employees        首次: 2024-01-15  最后: 2024-01-15  (NEW)
  \\DC01\SYSVOL                    首次: 2023-03-15  最后: 2024-01-16  (异常访问时间)

--- 可移动设备访问 ---
  E:\ (USB 驱动器)
    卷名称:    BACKUP_DRIVE
    首次访问: 2024-01-15 15:30:00 UTC
    最后访问:  2024-01-15 15:45:22 UTC
    浏览的文件夹数: 3 (E:\, E:\Backup, E:\Backup\Corporate_Data)

--- 已删除/不存在的路径 ---
  C:\ProgramData\Updates\                (文件夹已删除，shellbag 仍存在)
  C:\ProgramData\svc\                    (文件夹已删除，shellbag 仍存在)
  C:\Windows\Temp\tools\                 (文件夹已删除，shellbag 仍存在)

Summary:
  总共访问的唯一文件夹数:  1,690
  网络共享访问数:        4 (2 个在事件期间首次访问)
  可移动媒体:                1 个 USB 设备 (疑似数据中转)
  已删除文件夹证据:        3 个路径 (反取证指标)
  CSV 导出到:                /analysis/shellbag_output/
```