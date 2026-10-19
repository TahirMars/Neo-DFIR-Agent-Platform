---
id: analyzing-ransomware-payment-wallets
name: analyzing-ransomware-payment-wallets
name_zh: 分析·勒索软件·支付·钱包
description: 使用区块链分析工具追踪勒索软件加密货币支付流向。识别钱包集群，通过混合器和交易所追踪资金流动，并支持执法归因。激活涉及勒索软件支付追踪、比特币钱包分析、加密货币取证或区块链情报收集的请求。
domain: cybersecurity
subdomain: ransomware-defense
tags:
- ransomware
- blockchain
- cryptocurrency
- forensics
- threat-intelligence
- bitcoin
version: 1.0.0
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 分析·勒索软件·支付·钱包

## 使用时机
- 某个组织遭遇勒索软件攻击，勒索信中包含需调查的比特币或加密货币钱包地址
- 执法部门或事件响应人员需要追踪受害者支付赎金后的资金流向
- 威胁情报分析师通过事件中的支付基础设施集群归因勒索软件活动
- 调查人员需要确认勒索软件组织是否在多个受害者间重复使用钱包基础设施
- 合规或法律团队需要资金流向证据以进行起诉、制裁执行或保险索赔

**请勿使用**此技能进行实时支付拦截或直接与勒索软件运营商交互。所有分析都应基于公共区块链数据进行被动且只读的操作。

## 前置条件
- Python 3.8+，包含“requests”、“json”和“hashlib”库
- 可访问区块链浏览器 API（blockchain.com、WalletExplorer.com、Blockstream.info）
- 熟悉比特币交易模型（UTXO、输入、输出、更改地址）
- 了解常见混淆技术（混合器、滚筒、剥离链、跨链交换）
- 可选：Chainalysis Reactor 企业级集群分析许可证
- 可选：OXT.me 用于高级交易图可视化

## 工作流程
### 第1步：从勒索信中提取钱包地址

解析勒索信以识别付款地址：```
Common address formats:
  Bitcoin (P2PKH):   1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa  (starts with 1)
  Bitcoin (P2SH):    3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy  (starts with 3)
  Bitcoin (Bech32):  bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq (starts with bc1)
  Monero:            4... (95 characters, much harder to trace)
  Ethereum:          0x... (40 hex chars)
```### 第2步：查询区块链浏览器的交易历史

检索与钱包关联的所有交易：```python
import requests

def get_wallet_transactions(address):
    """Query blockchain.com API for address transactions."""
    url = f"https://blockchain.info/rawaddr/{address}"
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return {
        "address": address,
        "n_tx": data.get("n_tx", 0),
        "total_received_satoshi": data.get("total_received", 0),
        "total_sent_satoshi": data.get("total_sent", 0),
        "final_balance_satoshi": data.get("final_balance", 0),
        "transactions": data.get("txs", []),
    }
```### 第3步：绘制资金流图并识别集群

跟踪从勒索钱包到下游地址的输出：```
Fund Flow Analysis:
━━━━━━━━━━━━━━━━━━
Victim Payment ──► Ransom Wallet ──► Consolidation Wallet
                                  ├─► Mixer/Tumbler Service
                                  ├─► Exchange Deposit Address
                                  └─► Peel Chain (sequential small outputs)

Key indicators:
  - Consolidation: 多个赎金支付汇总到一个钱包
  - Peel chains: 顺序交易中输出金额逐渐减少
  - Mixer usage: 资金发送至已知混合器地址（Wasabi, Samourai, ChipMixer）
  - Exchange cashout: 存入已知交易所钱包（Binance, Kraken热钱包）
```### 第4步：与已知钱包数据库的交叉引用

根据已知的勒索软件基础设施检查地址：```python
# Check WalletExplorer for entity identification
def check_wallet_explorer(address):
    url = f"https://www.walletexplorer.com/api/1/address?address={address}&caller=research"
    resp = requests.get(url, timeout=30)
    data = resp.json()
    return {
        "wallet_id": data.get("wallet_id"),
        "label": data.get("label", "Unknown"),
        "is_exchange": data.get("is_exchange", False),
    }
```### 第5步：生成归因报告

将调查结果编译成结构化情报报告：```
RANSOMWARE WALLET ANALYSIS REPORT
====================================
Ransom Address:      bc1q...xyz
Family Attribution:  LockBit 3.0 (based on ransom note format)
Total Received:      4.25 BTC ($178,500 at time of payment)
Total Sent:          4.25 BTC (wallet fully drained)
Number of Payments:  3 (likely 3 separate victims)

FUND FLOW:
  Payment 1: 1.5 BTC → Consolidation wallet → Binance deposit
  Payment 2: 1.0 BTC → Wasabi Mixer → Unknown
  Payment 3: 1.75 BTC → Peel chain (12 hops) → OKX deposit

CLUSTER ANALYSIS:
  Related wallets: 47 addresses identified in same cluster
  Total cluster volume: 156.3 BTC ($6.5M USD)
  First activity: 2024-01-15
  Last activity: 2024-09-22
```## 验证

- 在查询API前确认钱包地址格式有效
- 交叉验证交易时间戳与已知事件时间线
- 通过检查公共输入所有权启发式验证集群关联
- 将结果与 OFAC SDN 列表比较获取受制裁地址
- 根据多个来源（WalletExplorer、OXT、Chainalysis）验证交易归属

## 关键概念

|术语 |定义|
|------|------------|
| **UTXO** |未花费的交易输出；比特币的基本单位，通过交易链追踪所有权|
| **聚类分析** |使用共同输入所有权和更改地址启发法对被认为由同一实体控制的多个比特币地址进行分组 |
| **剥离链** |一种洗钱模式，其中资金通过许多连续交易发送，每笔交易都会将少量资金转移到新地址 |
| **CoinJoin/混合器** |结合多个用户的交易来模糊发送者和接收者之间链接的隐私技术 |
| **共同输入所有权** |启发式假设单个交易的所有输入均由同一实体控制 |

## 工具和系统

- **Chainalysis Reactor**：具有实体归属和跨链追踪的企业区块链调查平台
- **WalletExplorer**：聚集比特币地址并标记已知服务（交易所、混合器、市场）的免费工具
- **OXT.me**：带有 UTXO 图分析的高级比特币交易可视化
- **Blockstream.info**：具有完整 API 访问权限的开源比特币区块浏览器
- **blockchain.com API**：用于查询比特币地址余额和交易历史的免费API
- **OFAC SDN 列表**：美国财政部批准的用于合规性检查的地址列表