---
id: analyzing-powershell-script-block-logging
name: analyzing-powershell-script-block-logging
name_zh: 分析·PowerShell·脚本·阻断·日志记录
description: 解析 Windows PowerShell 脚本块日志（事件 ID 4104）中的 EVTX 文件，用于检测混淆命令、编码负载和独立技术。利用
  python-evtx 提取并重建多块脚本，对 Base64 编码命令进行熵分析和模式匹配，检测 Invoke-Expression 滥用、下载支架和 AMSI
  绕过尝试。
domain: cybersecurity
subdomain: security-operations
tags:
- analyzing
- powershell
- script
- block
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 分析 PowerShell 脚本阻断日志

## 使用时机
- 调查需要分析 PowerShell 脚本块日志的安全事件时
- 为该域构建检测规则或威胁搜寻查询时
- 当 SOC 分析师需要这种分析类型的结构化程序时
- 验证相关攻击技术的安全监控覆盖范围时

## 前置条件
- 熟悉安全运营概念和工具
- 访问测试或实验室环境以安全执行
- 安装了所需依赖项的 Python 3.8+
- 任何测试活动的适当授权

## 说明

1. 安装依赖项：`pip install python-evtx lxml`
2. 收集 PowerShell 操作日志：`Microsoft-Windows-PowerShell%4Operational.evtx`
3. 使用 python-evtx 解析事件 ID 4104 条目，以提取 ScriptBlockText、ScriptBlockId 和 MessageNumber/MessageTotal，以进行多部分脚本重建。
4. 应用检测启发式：
   - Base64 编码命令（`-EncodedCommand`、`FromBase64String`）
   - 下载支架（`DownloadString`、`DownloadFile`、`Invoke-WebRequest`、`Net.WebClient`）
   - AMSI 绕过模式（`AmsiUtils`、`amsiInitFailed`）
   - 混淆指标（高熵、刻度线插入、字符串连接）
5. 生成包含重建脚本、风险评分和 MITRE ATT&CK 映射的报告。```bash
python scripts/agent.py --evtx-file /path/to/PowerShell-Operational.evtx --output ps_analysis.json
```

## 示例

### 检测编码命令执行

```python
import base64
if "-encodedcommand" in script_text.lower():
    encoded = script_text.split()[-1]
    decoded = base64.b64decode(encoded).decode("utf-16-le")
```

### 重建多块脚本
跨多个 4104 事件拆分的脚本共享一个“ScriptBlockId”。连接按“MessageNumber”排序的块以恢复完整的脚本。