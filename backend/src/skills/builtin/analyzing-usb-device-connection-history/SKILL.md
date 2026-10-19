---
id: analyzing-usb-device-connection-history
name: analyzing-usb-device-connection-history
name_zh: 分析·USB·设备·连接·历史
description: 调查 Windows 注册表、事件日志和 setupapi 日志中的 USB 设备连接历史，以追踪可移动介质的使用情况和潜在的数据泄露风险。涵盖取证分析流程、设备标识解析、驱动器号关联及时间线构建方法。
domain: cybersecurity
subdomain: digital-forensics
tags:
- forensics
- usb-forensics
- removable-media
- registry-analysis
- data-exfiltration
- device-history
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 分析 USB 设备连接历史

## 使用时机
- 当调查通过可移动存储设备潜在的数据泄露时
- 在内部威胁调查期间追踪 USB 设备的使用情况
- 用于合规性审核，验证可移动媒体策略的执行情况
- 将 USB 连接与文件访问和复制事件关联时
- 用于建立事件期间设备连接的时间表

## 前置条件
- 取证镜像或提取的注册表配置单元和事件日志
- 访问 SYSTEM、SOFTWARE 和 NTUSER.DAT 注册表配置单元
- SetupAPI 日志 (setupapi.dev.log)
- Windows 事件日志（系统、安全、DriverFrameworks-用户模式）
- USBDeview、USB 取证跟踪器或 RegRipper
- 了解 USB 设备标识（VID、PID、序列号）

## 工作流程
### 第 1 步：提取 USB 相关工件

```bash
# Mount forensic image and copy relevant artifacts
mount -o ro,loop,offset=$((2048*512)) /cases/case-2024-001/images/evidence.dd /mnt/evidence

mkdir -p /cases/case-2024-001/usb/

# Registry hives
cp /mnt/evidence/Windows/System32/config/SYSTEM /cases/case-2024-001/usb/
cp /mnt/evidence/Windows/System32/config/SOFTWARE /cases/case-2024-001/usb/
cp /mnt/evidence/Users/*/NTUSER.DAT /cases/case-2024-001/usb/

# SetupAPI logs (first connection timestamps)
cp /mnt/evidence/Windows/INF/setupapi.dev.log /cases/case-2024-001/usb/

# Event logs
cp /mnt/evidence/Windows/System32/winevt/Logs/System.evtx /cases/case-2024-001/usb/
cp "/mnt/evidence/Windows/System32/winevt/Logs/Microsoft-Windows-DriverFrameworks-UserMode%4Operational.evtx" \
   /cases/case-2024-001/usb/ 2>/dev/null
cp "/mnt/evidence/Windows/System32/winevt/Logs/Microsoft-Windows-Partition%4Diagnostic.evtx" \
   /cases/case-2024-001/usb/ 2>/dev/null
```### 第 2 步：解析 USBSTOR 注册表键```bash
# Extract USBSTOR entries from SYSTEM hive
python3 << 'PYEOF'
from Registry import Registry
import json

reg = Registry.Registry("/cases/case-2024-001/usb/SYSTEM")

# Find current ControlSet
select = reg.open("Select")
current = select.value("Current").value()
controlset = f"ControlSet{current:03d}"

# Parse USBSTOR
usbstor_path = f"{controlset}\\Enum\\USBSTOR"
usbstor = reg.open(usbstor_path)

devices = []
print("=== USBSTOR DEVICES ===\n")

for device_class in usbstor.subkeys():
    # Format: Disk&Ven_VENDOR&Prod_PRODUCT&Rev_REVISION
    class_name = device_class.name()
    parts = class_name.split('&')
    vendor = parts[1].replace('Ven_', '') if len(parts) > 1 else 'Unknown'
    product = parts[2].replace('Prod_', '') if len(parts) > 2 else 'Unknown'
    revision = parts[3].replace('Rev_', '') if len(parts) > 3 else 'Unknown'

    for instance in device_class.subkeys():
        serial = instance.name()
        last_write = instance.timestamp()

        device_info = {
            'vendor': vendor,
            'product': product,
            'revision': revision,
            'serial': serial,
            'last_connected': str(last_write),
        }

        # Get friendly name if available
        try:
            friendly = instance.value("FriendlyName").value()
            device_info['friendly_name'] = friendly
        except:
            pass

        # Get device parameters
        try:
            params = instance.subkey("Device Parameters")
            try:
                device_info['class_guid'] = params.value("ClassGUID").value()
            except:
                pass
        except:
            pass

        devices.append(device_info)
        print(f"Device: {vendor} {product}")
        print(f"  Serial: {serial}")
        print(f"  Last Connected: {last_write}")
        print(f"  Friendly Name: {device_info.get('friendly_name', 'N/A')}")
        print()

# Save results
with open('/cases/case-2024-001/analysis/usb_devices.json', 'w') as f:
    json.dump(devices, f, indent=2)

print(f"\nTotal USB storage devices found: {len(devices)}")
PYEOF
```### 第 3 步：提取驱动器号分配和用户关联```bash
# Parse MountedDevices from SYSTEM hive
python3 << 'PYEOF'
from Registry import Registry
import struct

reg = Registry.Registry("/cases/case-2024-001/usb/SYSTEM")

mounted = reg.open("MountedDevices")

print("=== MOUNTED DEVICES (Drive Letter Assignments) ===\n")
for value in mounted.values():
    name = value.name()
    data = value.value()

    if name.startswith("\\DosDevices\\"):
        drive_letter = name.replace("\\DosDevices\\", "")
        if len(data) > 24:
            # USB device - contains device path string
            try:
                device_path = data.decode('utf-16-le').strip('\x00')
                if 'USBSTOR' in device_path or 'USB#' in device_path:
                    print(f"  {drive_letter} -> {device_path}")
            except:
                pass
        else:
            # Fixed disk - contains disk signature + offset
            disk_sig = struct.unpack('<I', data[0:4])[0]
            offset = struct.unpack('<Q', data[4:12])[0]
            print(f"  {drive_letter} -> Disk Signature: 0x{disk_sig:08X}, Offset: {offset}")
PYEOF

# Parse user MountPoints2 (which user accessed which devices)
python3 << 'PYEOF'
from Registry import Registry
import os, glob

print("\n=== USER MOUNT POINTS (MountPoints2) ===\n")

for ntuser in glob.glob("/cases/case-2024-001/usb/NTUSER*.DAT"):
    try:
        reg = Registry.Registry(ntuser)
        mp2 = reg.open("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2")

        print(f"User hive: {os.path.basename(ntuser)}")
        for key in mp2.subkeys():
            guid = key.name()
            last_write = key.timestamp()
            if '{' in guid:
                print(f"  Volume: {guid} | Last accessed: {last_write}")
        print()
    except Exception as e:
        print(f"  Error parsing {ntuser}: {e}")
PYEOF
```### 第4步：从SetupAPI中提取首次连接时间戳```bash
# Parse setupapi.dev.log for USB device first-install timestamps
python3 << 'PYEOF'
import re

print("=== SETUPAPI USB DEVICE INSTALLATIONS ===\n")

with open('/cases/case-2024-001/usb/setupapi.dev.log', 'r', errors='ignore') as f:
    content = f.read()

# Find USB device installation sections
pattern = r'>>>\s+\[Device Install.*?\n.*?Section start (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*?\n(.*?)<<<'
matches = re.findall(pattern, content, re.DOTALL)

usb_installs = []
for timestamp, section in matches:
    if 'USBSTOR' in section or 'USB\\VID' in section:
        # Extract device ID
        dev_match = re.search(r'(USBSTOR\\[^\s]+|USB\\VID_\w+&PID_\w+[^\s]*)', section)
        if dev_match:
            device_id = dev_match.group(1)
            usb_installs.append({
                'first_install': timestamp,
                'device_id': device_id
            })
            print(f"  {timestamp} | {device_id}")

print(f"\nTotal USB installations found: {len(usb_installs)}")
PYEOF

# Parse Windows Event Logs for USB events
# Event IDs: 2003, 2010, 2100, 2102 (DriverFrameworks-UserMode)
# Event IDs: 6416 (Security - new external device recognized)
python3 << 'PYEOF'
import json
from evtx import PyEvtxParser

try:
    parser = PyEvtxParser("/cases/case-2024-001/usb/System.evtx")

    print("\n=== SYSTEM EVENT LOG USB EVENTS ===\n")
    for record in parser.records_json():
        data = json.loads(record['data'])
        event_id = str(data['Event']['System']['EventID'])

        # USB device connection events
        if event_id in ('20001', '20003', '10000', '10100'):
            timestamp = data['Event']['System']['TimeCreated']['#attributes']['SystemTime']
            event_data = data['Event'].get('UserData', data['Event'].get('EventData', {}))
            print(f"  [{timestamp}] EventID {event_id}: {json.dumps(event_data, default=str)[:200]}")
except Exception as e:
    print(f"Error: {e}")
PYEOF
```### 第 5 步：构建 USB 活动时间线和报告```bash
# Compile all USB evidence into a unified timeline
python3 << 'PYEOF'
import json, csv

timeline = []

# Load USBSTOR data
with open('/cases/case-2024-001/analysis/usb_devices.json') as f:
    devices = json.load(f)

for device in devices:
    timeline.append({
        'timestamp': device['last_connected'],
        'source': 'USBSTOR Registry',
        'device': f"{device['vendor']} {device['product']}",
        'serial': device['serial'],
        'event': 'Last Connected',
        'detail': device.get('friendly_name', '')
    })

# Sort chronologically
timeline.sort(key=lambda x: x['timestamp'])

# Write timeline CSV
with open('/cases/case-2024-001/analysis/usb_timeline.csv', 'w', newline='') as f:
    writer = csv.DictWriter(f, fieldnames=['timestamp', 'source', 'device', 'serial', 'event', 'detail'])
    writer.writeheader()
    writer.writerows(timeline)

print(f"USB Timeline: {len(timeline)} events written to usb_timeline.csv")

# Print summary
print("\n=== USB DEVICE SUMMARY ===")
for entry in timeline:
    print(f"  {entry['timestamp']} | {entry['device']} | {entry['serial'][:20]} | {entry['event']}")
PYEOF
```## 关键概念

| 概念 | 描述 |
|---------|-------------|
| USB存储 | 存储 USB 大容量存储设备识别和连接数据的注册表项 |
| VID/PID | 唯一标识 USB 设备制造商和型号的供应商 ID 和产品 ID |
| 设备序列号 | 单个 USB 设备的唯一标识符（某些设备共享序列号） |
| 已安装设备 | 将卷 GUID 和驱动器盘符映射到物理设备的注册表项 |
| 挂载点2 | 显示用户访问的卷的每用户注册表项 |
| SetupAPI日志 | Windows 驱动程序安装日志记录首次设备连接 |
| 设备容器 | 带有设备元数据和时间戳的软件配置单元中的注册表项 |
| EMMDgmt | 使用序列号和时间戳跟踪 ReadyBoost 兼容设备的注册表项 |

## 工具和系统

| 工具 | 目的 |
|------|---------|
| USB 取证追踪器 | USB设备历史提取专用工具 |
| USBDeview | NirSoft 工具列出连接到系统的所有 USB 设备 |
| RegRipper（usbstor 插件） | 从注册表配置单元自动提取 USB 工件 |
| 注册表浏览器 | USB相关密钥的交互式注册表分析 |
| Cuckoo | 自动收集 USB 相关工件 |
| Plaso/log2timeline | 时间线创建，包括 USB 连接事件 |
| FTK 成像仪 | 法医成像，包括可移动介质 |
| Carbon Black | 具有 USB 设备历史记录搜寻工件的端点代理 |

## 常见场景

**场景 1：离职员工泄露数据**
提取 USBSTOR 条目以识别曾经连接的所有 USB 设备，将设备序列号与 MountPoints2 相关联以确认用户访问，将时间戳与文件访问日志交叉引用并跳转列表最近的文件，检查 USN 日志中的大文件复制模式。

**场景 2：安全系统上未经授权的设备**
根据批准的设备列表审核所有 USBSTOR 条目，通过与公司批准的硬件不匹配的 VID/PID 识别未经授权的设备，确定未经授权的设备首次和最后一次连接的时间，检查是否传输了任何数据。

**场景 3：通过 USB 传送恶意软件**
识别在恶意软件执行之前连接的 USB 设备（预取时间戳），提取设备序列号和供应商信息，检查设备是否启用了自动运行，在预取和 ShimCache 中查找从可移动驱动器盘符启动的可执行文件。

**场景 4：跨多个系统跟踪特定 USB 驱动器**
在 USBSTOR 中跨所有取证图像搜索相同的设备序列号，构建驱动器连接到哪些系统以及何时连接的地图，识别设备在组织中的时间顺序路径，与网络共享访问日志相关联。

## 输出格式

```
USB Device History Analysis:
  System: DESKTOP-ABC123 (Windows 10 Pro)
  Total USB Storage Devices: 12
  Analysis Sources: USBSTOR, MountedDevices, MountPoints2, SetupAPI, Event Logs

  Device Inventory:
    1. Kingston DataTraveler 3.0 (Serial: 0019E06B4521A2B0)
       First Connected:  2024-01-10 09:15:32 (SetupAPI)
       Last Connected:   2024-01-18 14:30:00 (USBSTOR)
       Drive Letter:     E:
       User Access:      suspect_user (MountPoints2)

    2. WD My Passport (Serial: 575834314131363035)
       First Connected:  2024-01-15 20:00:00
       Last Connected:   2024-01-15 23:45:00
       Drive Letter:     F:
       User Access:      suspect_user

  Suspicious Findings:
    - Kingston drive connected 15 times during investigation period
    - WD Passport connected only once, late evening (unusual hours)
    - Unknown device (VID_1234&PID_5678) connected 2024-01-17, no matching approved device

  Timeline: /cases/case-2024-001/analysis/usb_timeline.csv
```