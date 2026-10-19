---
id: analyzing-linux-kernel-rootkits
name: analyzing-linux-kernel-rootkits
description: 结合 Volatility3 Linux 插件与 rkhunter 等检测内核 rootkit、隐藏模块与挂钩。
domain: cybersecurity
subdomain: digital-forensics
tags:
- rootkit
- linux
- kernel
- volatility3
- memory-forensics
- malware-analysis
- rkhunter
- forensics
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 分析 Linux 内核 Rootkit

## 概述

Linux kernel rootkits operate at ring 0, modifying kernel data structures to hide processes, files, network connections, and kernel modules from userspace tools. Detection requires either memory forensics (analyzing physical memory dumps with Volatility3) or cross-view analysis (comparing /proc, /sys, and kernel data structures for inconsistencies). 本技能涵盖 using Volatility3 Linux plugins to detect syscall table hooks, hidden kernel modules, and modified function pointers, supplemented by live system scanning with rkhunter and chkrootkit.


## 使用时机

- 在需要运用本技能进行分析的安全事件调查中
- 需要为本领域构建检测规则或威胁狩猎查询时
- SOC 分析师需要此类分析的结构化流程时
- 需要验证与相关攻击技术有关的安全监控覆盖时

## 前置条件

- Volatility3 installed (pip install volatility3)
- Linux memory dump (acquired via LiME, AVML, or /proc/kcore)
- Volatility3 Linux symbol table (ISF) matching the target kernel version
- rkhunter and chkrootkit for live system scanning
- Reference known-good kernel image for comparison

## 步骤

### 第 1 步：Acquire Memory Dump
Capture Linux physical memory using LiME kernel module or AVML for cloud instances.

### 第 2 步：Analyze with Volatility3
Run linux.check_syscall, linux.lsmod, linux.hidden_modules, and linux.check_idt plugins to detect rootkit artifacts.

### 第 3 步：Cross-View Analysis
Compare module lists from /proc/modules, lsmod, and /sys/module to identify modules hidden from one view but present in another.

### 第 4 步：Live System Scanning
Run rkhunter and chkrootkit to detect known rootkit signatures, suspicious files, and modified system binaries.

## 预期输出

JSON report containing detected syscall hooks, hidden kernel modules, modified IDT entries, suspicious /proc discrepancies, and rkhunter findings.

## Example Output

```text
$ sudo python3 rootkit_analyzer.py --memory /evidence/linux-mem.lime --profile Ubuntu2204

Linux Kernel Rootkit Analysis Report
=====================================
Memory Image: /evidence/linux-mem.lime
Kernel Version: 5.15.0-91-generic (Ubuntu 22.04 LTS)
Analysis Time: 2024-01-18 09:15:32 UTC

[+] Scanning syscall table for hooks...
    Syscall Table Base: 0xffffffff82200300
    Total syscalls checked: 449

    HOOKED SYSCALLS DETECTED:
    ┌─────────┬──────────────────┬──────────────────────┬──────────────────────┐
    │ NR      │ Syscall          │ Expected Address     │ Current Address      │
    ├─────────┼──────────────────┼──────────────────────┼──────────────────────┤
    │ 0       │ sys_read         │ 0xffffffff8139a0e0   │ 0xffffffffc0a12000   │
    │ 2       │ sys_open         │ 0xffffffff8139b340   │ 0xffffffffc0a12180   │
    │ 78      │ sys_getdents64   │ 0xffffffff813f5210   │ 0xffffffffc0a12300   │
    │ 62      │ sys_kill         │ 0xffffffff8110c4a0   │ 0xffffffffc0a12480   │
    └─────────┴──────────────────┴──────────────────────┴──────────────────────┘
    WARNING: 4 syscall hooks detected - rootkit behavior confirmed

[+] Checking for hidden kernel modules...
    Loaded modules (lsmod):         147
    Modules in kobject list:        149
    HIDDEN MODULES:
      - "netfilter_helper" at 0xffffffffc0a10000 (size: 12288)
      - "kworker_sched"    at 0xffffffffc0a14000 (size: 8192)

[+] Scanning /proc for discrepancies...
    Processes in task_struct list: 234
    Processes visible in /proc:   231
    HIDDEN PROCESSES:
      - PID 31337  cmd: "[kworker/0:3]"   (disguised as kernel thread)
      - PID 31442  cmd: "rsyslogd"         (fake, real rsyslogd is PID 892)
      - PID 31500  cmd: ""                 (unnamed process)

[+] Checking IDT entries...
    IDT entries scanned: 256
    Modified entries: 0 (clean)

[+] Running rkhunter scan...
    Checking for known rootkits:        68 variants checked
    Diamorphine rootkit:                WARNING - signatures match
    System binary checks:
      /usr/bin/ps:     MODIFIED (SHA-256 mismatch)
      /usr/bin/netstat: MODIFIED (SHA-256 mismatch)
      /usr/bin/ls:     MODIFIED (SHA-256 mismatch)
      /usr/sbin/ss:    OK

[+] Network analysis...
    Hidden connections (not in /proc/net/tcp):
      ESTABLISHED  0.0.0.0:0 -> 198.51.100.47:4443 (PID 31337)
      ESTABLISHED  0.0.0.0:0 -> 198.51.100.47:8080 (PID 31442)

Summary:
  Rootkit Type:         Loadable Kernel Module (LKM)
  Probable Family:      Diamorphine variant
  Syscall Hooks:        4 (read, open, getdents64, kill)
  Hidden Modules:       2
  Hidden Processes:     3
  Hidden Connections:   2 (C2: 198.51.100.47)
  Modified Binaries:    3 (/usr/bin/ps, netstat, ls)
  Risk Level:           CRITICAL
```