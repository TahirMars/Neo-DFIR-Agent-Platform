---
id: analyzing-persistence-mechanisms-in-linux
name: analyzing-persistence-mechanisms-in-linux
name_zh: 分析·持久化·机制·Linux
description: 使用auditd和文件完整性监控检测Linux持久性机制，包括crontab条目、systemd服务单元、LD_PRELOAD劫持、bashrc修改和authorized_keys后门。扫描所有持久性向量并关联审核日志以构建时间线。
domain: cybersecurity
subdomain: threat-hunting
tags:
- linux-persistence
- crontab
- systemd
- ld-preload
- auditd
- threat-hunting
- incident-response
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 分析·持久化·机制·Linux

## 概述
攻击者通过`crontab`作业、`systemd`服务/计时器单元、`LD_PRELOAD`库注入、shell配置文件修改（`.bashrc`、`.profile`）、SSH `authorized_keys`后门和init脚本操作在Linux系统上建立持久性。该技能扫描所有已知的持久性向量，检查文件时间戳和完整性，并将结果与审核日志关联起来以构建持久性安装的时间表。

## 使用时机
- 在调查需要分析Linux中的持久性机制的安全事件时
- 为该域构建检测规则或威胁搜寻查询时
- 当SOC分析师需要这种分析类型的结构化程序时
- 验证相关攻击技术的安全监控覆盖范围时

## 前置条件
- 目标Linux系统（或取证映像）上的root或sudo访问
- `auditd`在持久性路径上配置了文件监视规则
- Python 3.8+带有标准库（`os`、`subprocess`、`json`）
- 可选：用于文件完整性监控警报的OSSEC/Wazuh代理

## 步骤

1. **扫描Crontab条目** — 枚举所有用户`crontab`、`/etc/cron.d/`、`/etc/cron.daily/`和anacron作业以查找可疑命令
2. **审核Systemd单元** — 检查`/etc/systemd/system/`和`~/.config/systemd/user/`是否有非包管理的服务和计时器单元
3. **检测LD_PRELOAD劫持** — 检查`/etc/ld.so.preload`和`LD_PRELOAD`环境变量以注入共享库
4. **检查Shell配置文件** — 扫描`.bashrc`、`.bash_profile`、`.profile`、`/etc/profile.d/`以查找注入的命令或反向shell
5. **检查SSH授权密钥** — 审核所有`authorized_keys`文件中是否存在带有命令限制的未经授权的公钥
6. **关联审核日志** — 在持久性路径上搜索审核日志以查找文件修改事件以构建安装时间线
7. **生成持久性报告** — 生成所有发现的持久性机制的风险评分报告

## 预期输出

- 包含风险评分的所有持久性机制的JSON报告
- 从`auditd`相关性中持久化安装的时间表
- MITRE ATT&CK技术映射（T1053、T1543、T1574、T1546）
- 针对每个检测到的持久性机制的修复命令