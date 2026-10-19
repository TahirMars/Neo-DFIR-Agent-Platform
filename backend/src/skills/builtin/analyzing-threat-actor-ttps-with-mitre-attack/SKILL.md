---
id: analyzing-threat-actor-ttps-with-mitre-attack
name: analyzing-threat-actor-ttps-with-mitre-attack
name_zh: 分析·威胁·攻击者·TTP·MITRE·攻击
description: MITRE ATT&CK 是一个基于现实世界观察的全球性对手战术、技术与程序（TTP）知识库。该技能涉及将威胁行为者的活动系统性地映射到
  ATT&CK 框架，使用 ATT&CK 导航器构建技术覆盖热图，识别检测缺口并生成可操作的情报报告，将观察到的 IOC 与企业、移动和 ICS 矩阵中的特定对手技术进行关联。
domain: cybersecurity
subdomain: threat-intelligence
tags:
- threat-intelligence
- cti
- ioc
- mitre-attack
- stix
- ttp-analysis
- threat-actors
version: '1.0'
author: mahipal
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- report
- general_chat
---

# 分析·威胁·攻击者·TTP·MITRE·攻击

## 概述
MITRE ATT&CK 是一个全球可访问的基于现实世界观察的对手战术、技术与程序（TTP）知识库。该技能涵盖将威胁行为者行为系统性地映射到 ATT&CK 框架、使用 ATT&CK 导航器构建技术覆盖热图、识别检测缺口以及生成可操作的情报报告，将观察到的 IOC 与企业、移动和 ICS 矩阵中的特定对手技术进行关联。

## 使用时机
- 调查需要分析具有斜接攻击的威胁参与者 TTP 的安全事件时
- 构建检测规则或威胁搜寻查询时
- 当 SOC 分析师需要这种分析类型的结构化流程时
- 验证相关攻击技术的安全监控覆盖范围时

## 前置条件
- Python 3.9+ 带有 `mitreattack-python`、`attackcti`、`stix2` 库
- MITRE ATT&CK Navigator（基于网络或本地部署）
- 了解 ATT&CK 矩阵结构：战术、技术、子技术
- 访问威胁情报报告或 MISP/OpenCTI 以获取威胁行为者数据
- 熟悉 STIX 2.1 攻击模式对象

## 关键概念

### ATT&CK 矩阵结构
ATT&CK 企业矩阵将对手行为组织为 14 种策略（“为什么”），包含技术（“如何”）和子技术（具体实现）。每种技术都关联有数据源、检测方法、缓解措施以及来自威胁组的真实程序示例。

### 威胁组概况
ATT&CK 对 140 多个威胁组织（例如 APT28、APT29、Lazarus Group、FIN7）进行了分类，并记录其技术使用情况。每个组配置文件包括别名、目标行业、相关活动、使用的软件以及具有程序级详细信息的技术映射。

### ATT&CK 导航器
ATT&CK Navigator 是一款基于 Web 的工具，用于创建自定义 ATT&CK 矩阵可视化。分析师创建图层（JSON 文件），用分数、颜色、注释和元数据对技术进行标注，以可视化威胁参与者的覆盖范围、检测能力或风险评估。

## 工作流程
### 第 1 步：以编程方式查询 ATT&CK 数据

```python
from attackcti import attack_client
import json

# Initialize ATT&CK client (queries MITRE TAXII server)
lift = attack_client()

# Get all Enterprise techniques
enterprise_techniques = lift.get_enterprise_techniques()
print(f"Total Enterprise techniques: {len(enterprise_techniques)}")

# Get all threat groups
groups = lift.get_groups()
print(f"Total threat groups: {len(groups)}")

# Get specific group by name
apt29 = [g for g in groups if 'APT29' in g.get('name', '')]
if apt29:
    group = apt29[0]
    print(f"Group: {group['name']}")
    print(f"Aliases: {group.get('aliases', [])}")
    print(f"Description: {group.get('description', '')[:200]}")
```

### 第 2 步：将威胁行为者映射到 ATT&CK 技术

```python
from attackcti import attack_client

lift = attack_client()

# Get techniques used by APT29
apt29_techniques = lift.get_techniques_used_by_group("G0016")  # APT29 group ID

technique_map = {}
for entry in apt29_techniques:
    tech_id = entry.get("external_references", [{}])[0].get("external_id", "")
    tech_name = entry.get("name", "")
    description = entry.get("description", "")
    tactic_refs = [
        phase.get("phase_name", "")
        for phase in entry.get("kill_chain_phases", [])
    ]

    technique_map[tech_id] = {
        "name": tech_name,
        "tactics": tactic_refs,
        "description": description[:300],
    }

print(f"\nAPT29 uses {len(technique_map)} techniques:")
for tid, info in sorted(technique_map.items()):
    print(f"  {tid}: {info['name']} [{', '.join(info['tactics'])}]")
```

### 第 3 步：生成 ATT&CK 导航器图层

```python
import json

def create_navigator_layer(group_name, technique_map, description=""):
    """Generate ATT&CK Navigator layer JSON for a threat group."""
    techniques_list = []
    for tech_id, info in technique_map.items():
        techniques_list.append({
            "techniqueID": tech_id,
            "tactic": info["tactics"][0] if info["tactics"] else "",
            "color": "#ff6666",  # Red for observed techniques
            "comment": info["description"][:200],
            "enabled": True,
            "score": 100,
            "metadata": [
                {"name": "group", "value": group_name},
            ],
        })

    layer = {
        "name": f"{group_name} TTP Coverage",
        "versions": {
            "attack": "16.1",
            "navigator": "5.1.0",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": description or f"Techniques attributed to {group_name}",
        "filters": {"platforms": ["Windows", "Linux", "macOS", "Cloud"]},
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False,
        },
        "hideDisabled": False,
        "techniques": techniques_list,
        "gradient": {
            "colors": ["#ffffff", "#ff6666"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "Observed technique", "color": "#ff6666"},
            {"label": "Not observed", "color": "#ffffff"},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }

    return layer


# Generate and save layer
layer = create_navigator_layer("APT29", technique_map, "APT29 (Cozy Bear) TTP analysis")
with open("apt29_navigator_layer.json", "w") as f:
    json.dump(layer, f, indent=2)
print("[+] Navigator layer saved to apt29_navigator_layer.json")
```

### 第 4 步：识别检测缺口

```python
from attackcti import attack_client

lift = attack_client()

# Get all techniques with data sources
all_techniques = lift.get_enterprise_techniques()

# Build data source coverage map
data_source_coverage = {}
for tech in all_techniques:
    tech_id = tech.get("external_references", [{}])[0].get("external_id", "")
    data_sources = tech.get("x_mitre_data_sources", [])

    for ds in data_sources:
        if ds not in data_source_coverage:
            data_source_coverage[ds] = []
        data_source_coverage[ds].append(tech_id)

# Compare threat actor techniques against available detections
detected_techniques = {"T1059", "T1071", "T1566"}  # Example: techniques you can detect
actor_techniques = set(technique_map.keys())

covered = actor_techniques.intersection(detected_techniques)
gaps = actor_techniques - detected_techniques

print(f"\n=== Detection Gap Analysis for APT29 ===")
print(f"Actor techniques: {len(actor_techniques)}")
print(f"Detected: {len(covered)} ({len(covered)/len(actor_techniques)*100:.0f}%)")
print(f"Gaps: {len(gaps)} ({len(gaps)/len(actor_techniques)*100:.0f}%)")
print(f"\nUndetected techniques:")
for tech_id in sorted(gaps):
    if tech_id in technique_map:
        print(f"  {tech_id}: {technique_map[tech_id]['name']}")
```

### 第 5 步：跨组技术比较

```python
from attackcti import attack_client

lift = attack_client()

# Compare techniques across multiple groups
groups_to_compare = {
    "G0016": "APT29",
    "G0007": "APT28",
    "G0032": "Lazarus Group",
}

group_techniques = {}
for gid, gname in groups_to_compare.items():
    techs = lift.get_techniques_used_by_group(gid)
    tech_ids = set()
    for t in techs:
        tid = t.get("external_references", [{}])[0].get("external_id", "")
        if tid:
            tech_ids.add(tid)
    group_techniques[gname] = tech_ids

# Find common and unique techniques
all_groups = list(group_techniques.keys())
common_to_all = set.intersection(*group_techniques.values())
print(f"\nTechniques common to all {len(all_groups)} groups: {len(common_to_all)}")
for tid in sorted(common_to_all):
    print(f"  {tid}")

for gname, techs in group_techniques.items():
    unique = techs - set.union(*[t for n, t in group_techniques.items() if n != gname])
    print(f"\nUnique to {gname}: {len(unique)} techniques")
```

## 验证标准

- 通过 TAXII 服务器或本地副本成功查询 ATT&CK 数据
- 威胁行为者通过程序示例映射到特定技术
- ATT&CK 导航器图层 JSON 有效并正确渲染
- 检测缺口分析识别出未被监控的技术
- 跨组比较揭示共同和独特的 TTP
- 输出可用于检测工程优先级排序

## 参考资料
- [MITRE ATT&CK](https://attack.mitre.org/)
- [ATT&CK 导航器](https://mitre-attack.github.io/attack-navigator/)
- [attackcti Python 库](https://github.com/OTRF/ATTACK-Python-Client)
- [ATT&CK STIX 数据](https://github.com/mitre/cti)
- [ATT&CK 团体](https://attack.mitre.org/groups/)