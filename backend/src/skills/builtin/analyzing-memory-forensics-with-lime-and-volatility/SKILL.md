---
id: analyzing-memory-forensics-with-lime-and-volatility
name: analyzing-memory-forensics-with-lime-and-volatility
description: LiME 采集 Linux 内存后，用 Volatility 3（linux.*）提取进程、bash、套接字等。
domain: cybersecurity
subdomain: security-operations
tags:
- analyzing
- memory
- forensics
- with
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 使用 LiME 与 Volatility 进行内存取证


## 使用时机

- 在需要运用本技能进行分析的安全事件调查中
- 需要为本领域构建检测规则或威胁狩猎查询时
- SOC 分析师需要此类分析的结构化流程时
- 需要验证与相关攻击技术有关的安全监控覆盖时

## 前置条件

- 熟悉安全运营概念与工具
- 可在测试或实验环境中安全执行
- 已安装 Python 3.8+ 及所需依赖
- 具备开展测试活动的适当授权

## 说明

Acquire Linux memory using LiME kernel module, then analyze with Volatility 3
to extract forensic artifacts from the memory image.

```bash
# LiME acquisition
insmod lime-$(uname -r).ko "path=/evidence/memory.lime format=lime"

# Volatility 3 analysis
vol3 -f /evidence/memory.lime linux.pslist
vol3 -f /evidence/memory.lime linux.bash
vol3 -f /evidence/memory.lime linux.sockstat
```

```python
import volatility3
from volatility3.framework import contexts, automagic
from volatility3.plugins.linux import pslist, bash, sockstat

# Programmatic Volatility 3 usage
context = contexts.Context()
automagics = automagic.available(context)
```

Key analysis steps:
1. Acquire memory with LiME (format=lime or format=raw)
2. List processes with linux.pslist, compare with linux.psscan
3. Extract bash command history with linux.bash
4. List network connections with linux.sockstat
5. Check loaded kernel modules with linux.lsmod for rootkits

## 示例

```bash
# Full forensic workflow
vol3 -f memory.lime linux.pslist | grep -v "\[kthread\]"
vol3 -f memory.lime linux.bash
vol3 -f memory.lime linux.malfind
vol3 -f memory.lime linux.lsmod
```