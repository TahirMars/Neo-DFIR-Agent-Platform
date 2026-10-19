---
id: analyzing-network-flow-data-with-netflow
name: analyzing-network-flow-data-with-netflow
description: 解析 NetFlow v9/IPFIX 协议，识别扫描活动、数据外泄信标及流量异常模式。适用于安全事件调查、检测规则构建和威胁狩猎场景。
domain: cybersecurity
subdomain: network-security
tags:
- analyzing
- network
- flow
- data
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
name_zh: 分析·网络·流·数据·NetFlow
neo_agents:
- forensic
- general_chat
---

# 使用 NetFlow 分析网络流数据

## 使用时机

- 在需要运用本技能进行分析的安全事件调查中
- 需要为本领域构建检测规则或威胁狩猎查询时
- SOC 分析师需要此类分析的结构化流程时
- 需要验证与相关攻击技术有关的安全监控覆盖时

## 前置条件

- 熟悉网络安全概念与工具
- 可在测试或实验环境中安全执行
- 已安装 Python 3.8+ 及所需依赖
- 具备开展测试活动的适当授权

## 说明

1. 安装依赖：`pip install netflow`
2. 从路由器收集 NetFlow/IPFIX 数据或使用内置收集器：`python -m netflow.collector -p 9995`
3. 使用 `netflow.parse_packet()` 解析捕获的流数据
4. 分析流量特征：
   - 端口扫描：同一源地址向多个目标地址发起相同端口连接
   - 数据外泄：向非常规目标地址发送高字节数的出站流量
   - C2信标：具有固定时间间隔的周期性连接
   - 流量异常：超出基线阈值的流量激增
5. 生成优先级排序的发现报告

```bash
python scripts/agent.py --flow-file captured_flows.json --output netflow_report.json
```

## 示例

### 解析 NetFlow v9 数据包
```python
import netflow
data, _ = netflow.parse_packet(raw_bytes, templates={})
for flow in data.flows:
    print(flow.IPV4_SRC_ADDR, flow.IPV4_DST_ADDR, flow.IN_BYTES)
```