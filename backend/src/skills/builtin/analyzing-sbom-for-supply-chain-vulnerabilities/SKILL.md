---
id: analyzing-sbom-for-supply-chain-vulnerabilities
name: analyzing-sbom-for-supply-chain-vulnerabilities
name_zh: 分析·SBOM·供应链·链条·漏洞
description: 解析 CycloneDX 和 SPDX JSON 格式的软件物料清单 (SBOM)，通过 NVD 2.0 API 将组件与 NVD CVE
  数据库关联，识别供应链漏洞。构建依赖关系图、计算风险评分、识别传递漏洞路径并生成合规性报告。激活涉及 SBOM 分析、软件构成分析、供应链安全评估、依赖性漏洞扫描、CycloneDX/SPDX
  解析或 CVE 关联的请求。
domain: cybersecurity
subdomain: supply-chain-security
tags:
- SBOM
- CycloneDX
- SPDX
- NVD
- CVE
- supply-chain
- dependency-analysis
- syft
- grype
version: 1.0.0
author: mukul975
license: Apache-2.0
locale: zh-CN
neo_agents:
- forensic
- general_chat
---

# 分析·SBOM·供应链·漏洞

## 使用时机
- 新的监管要求（EO 14028、EU CRA）强制要求对软件交付进行 SBOM 分析
- 安全团队需要通过扫描供应商提供的 SBOM 来评估第三方风险
- CI/CD 管道需要针对生成的 SBOM 进行自动漏洞检查
- 事件响应需要确定新披露的 CVE 是否影响已部署的软件
- 采购团队要求对软件采购进行供应链风险评估

**请勿使用**对实时系统进行运行时漏洞扫描；使用容器扫描工具（Trivy、Grype CLI）或基于主机的漏洞扫描器（Nessus、Qualys）。

## 前置条件
- CycloneDX JSON (v1.4+) 或 SPDX JSON (v2.3+) 格式的 SBOM 文件
- Python 3.9+，安装了 requests、networkx 和打包库
- NVD API 密钥（免费，来自 https://nvd.nist.gov/developers/request-an-api-key）以获得更高的速率限制
- 网络访问 NVD API (https://services.nvd.nist.gov/rest/json/cves/2.0)
- 可选：syft 用于 SBOM 生成，grype 用于交叉验证

## 工作流程
### 第1步：生成SBOM（如果没有提供）

使用 syft 从容器映像或项目目录创建 SBOM：```bash
# Generate CycloneDX JSON from a container image
syft alpine:latest -o cyclonedx-json > sbom-cyclonedx.json

# Generate SPDX JSON from a project directory
syft dir:/path/to/project -o spdx-json > sbom-spdx.json

# Generate from a running container
syft docker:my-app-container -o cyclonedx-json > sbom.json
```Syft 支持 30 多个包生态系统，包括 npm、PyPI、Maven、Go 模块、apt、apk 和 RPM。生成的 SBOM 包括包名称、版本、许可证、CPE 标识符和 PURL（包 URL）引用。

### 第2步：解析SBOM并提取组件

解析 SBOM 以提取所有软件组件及其标识符：

**CycloneDX JSON 结构：**```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [
    {
      "type": "library",
      "name": "lodash",
      "version": "4.17.20",
      "purl": "pkg:npm/lodash@4.17.20",
      "cpe": "cpe:2.3:a:lodash:lodash:4.17.20:*:*:*:*:*:*:*",
      "licenses": [{"license": {"id": "MIT"}}]
    }
  ],
  "dependencies": [
    {"ref": "pkg:npm/express@4.18.2", "dependsOn": ["pkg:npm/lodash@4.17.20"]}
  ]
}
```**SPDX JSON 结构：**```json
{
  "spdxVersion": "SPDX-2.3",
  "packages": [
    {
      "name": "lodash",
      "versionInfo": "4.17.20",
      "externalRefs": [
        {"referenceType": "purl", "referenceLocator": "pkg:npm/lodash@4.17.20"},
        {"referenceType": "cpe23Type", "referenceLocator": "cpe:2.3:a:lodash:lodash:4.17.20:*:*:*:*:*:*:*"}
      ],
      "licenseConcluded": "MIT"
    }
  ],
  "relationships": [
    {"spdxElementId": "SPDXRef-express", "relatedSpdxElement": "SPDXRef-lodash",
     "relationshipType": "DEPENDS_ON"}
  ]
}
```### 第3步：将组件与 NVD CVE 数据库关联

查询 NVD 2.0 API 以查找每个组件的已知漏洞：```python
import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def search_cves_by_cpe(cpe_name, api_key=None):
    params = {"cpeName": cpe_name, "resultsPerPage": 50}
    headers = {"apiKey": api_key} if api_key else {}
    resp = requests.get(NVD_API, params=params, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json().get("vulnerabilities", [])

def search_cves_by_keyword(keyword, version=None, api_key=None):
    params = {"keywordSearch": keyword, "resultsPerPage": 50}
    headers = {"apiKey": api_key} if api_key else {}
    resp = requests.get(NVD_API, params=params, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json().get("vulnerabilities", [])
```NVD API 支持按 CPE 名称（最精确）、关键字、CVE ID 和日期范围进行搜索。速率限制：没有 API 密钥的情况下 5 个请求/30 秒，有密钥的情况下 50 个请求/30 秒。

### 第4步：构建依赖图并识别传递风险

构建依赖关系的有向图来跟踪漏洞传播：```python
import networkx as nx

def build_dependency_graph(sbom):
    G = nx.DiGraph()
    # Add nodes for each component
    for comp in sbom["components"]:
        G.add_node(comp["purl"], name=comp["name"], version=comp["version"])
    # Add edges from dependency relationships
    for dep in sbom.get("dependencies", []):
        for child in dep.get("dependsOn", []):
            G.add_edge(dep["ref"], child)
    return G
```传递依赖分析识别那些不直接包含但通过依赖链引入的组件。深度嵌套传递依赖项（例如，4 层深度）中的漏洞仍然存在风险，但可能更难以修复。

风险评估的关键图表指标：
- **入度**：有多少个组件依赖于此（高入度=高爆炸半径）
- **到根的最短路径**：距应用程序入口点的距离（更近=更容易利用）
- **之间的中心性**：位于许多依赖路径上的组件（瓶颈风险）

### 第5步：计算风险评分

将漏洞数据聚合为组件和总体风险评分：```
Risk Score Calculation:
━━━━━━━━━━━━━━━━━━━━━━
Component Risk = max(CVSS scores of all CVEs affecting the component)

Weighted Risk = Component Risk * Dependency Factor
  where Dependency Factor = 1.0 + (0.1 * in_degree)
  (more dependents = higher organizational impact)

Overall SBOM Risk = weighted average of all component risks
  weighted by dependency centrality

Risk Levels:
  CRITICAL:  CVSS >= 9.0 or known exploited (CISA KEV)
  HIGH:      CVSS >= 7.0
  MEDIUM:    CVSS >= 4.0
  LOW:       CVSS < 4.0
```### 第6步：与 Grype 交叉验证

使用 grype 独立扫描 SBOM 并比较结果：```bash
# Scan CycloneDX SBOM with grype
grype sbom:sbom-cyclonedx.json -o json > grype-results.json

# Scan SPDX SBOM
grype sbom:sbom-spdx.json -o table

# Filter by severity
grype sbom:sbom-cyclonedx.json --only-fixed --fail-on critical
```Grype 从 NVD、GitHub Security Advisories、Alpine SecDB、Red Hat、Debian、Ubuntu、Amazon Linux 和 Oracle 安全数据库中提取漏洞数据，提供比单独 NVD 更广泛的覆盖范围。

### 第7步：生成合规报告

生成适合法规遵从性的结构化报告：```
SBOM VULNERABILITY ANALYSIS REPORT
====================================
SBOM File:         app-sbom-cyclonedx.json
Format:            CycloneDX v1.5
Analysis Date:     2026-03-19
Total Components:  247
Total Dependencies: 1,842 (direct: 34, transitive: 213)

VULNERABILITY SUMMARY
  Critical:  3 components / 5 CVEs
  High:      11 components / 18 CVEs
  Medium:    27 components / 41 CVEs
  Low:       8 components / 12 CVEs

CRITICAL FINDINGS
1. lodash@4.17.20
   CVE-2021-23337 (CVSS 7.2) - Command Injection via template
   CVE-2020-28500 (CVSS 5.3) - ReDoS in trimEnd
   Dependents: 14 components (high blast radius)
   Fix: Upgrade to 4.17.21+

2. log4j-core@2.14.1
   CVE-2021-44228 (CVSS 10.0) - Log4Shell RCE [CISA KEV]
   CVE-2021-45046 (CVSS 9.0) - Incomplete fix bypass
   Dependents: 8 components
   Fix: Upgrade to 2.17.1+

DEPENDENCY GRAPH RISKS
  Most depended-on: core-util@1.2.3 (47 dependents)
  Deepest chain: app -> framework -> adapter -> codec -> zlib (5 levels)
  Bottleneck components: 3 components on >50% of dependency paths

LICENSE COMPLIANCE
  Copyleft licenses found: 2 (GPL-3.0 in libxml2, AGPL-3.0 in mongodb-driver)
  Review required for commercial distribution
```## 关键概念

| 术语 | 定义 |
|------|------------|
| **SBOM** | 软件物料清单；软件产品中所有组件、库和依赖项的正式清单 |
| **CycloneDX** | OWASP 维护的 SBOM 标准支持 JSON、XML 和 protobuf 格式以及依赖关系图和漏洞数据 |
| **SPDX** | Linux 基金会 SBOM 标准专注于许可证合规性，支持包、文件和片段级详细信息 |
| **PURL** | 包网址；用于识别跨生态系统的软件包的标准化方案（例如，pkg:npm/lodash@4.17.21） |
| **CPE** | 通用平台枚举；用于与 NVD CVE 数据关联的 IT 产品的 NIST 命名方案 |
| **NVD** | 国家漏洞数据库；美国政府按 CVE 标识符索引的漏洞数据存储库 |
| **传递依赖** | 未直接声明而是通过直接依赖项的依赖项链拉入的依赖项 |
| **CISA KEV** | CISA 已知被利用的漏洞目录；CVE 已被证实在野外被积极利用 |

## 工具和系统

- **syft** (Anchore)：开源 SBOM 生成器，支持 30 多个封装生态系统和 CycloneDX/SPDX 输出
- **grype**（Anchore）：接受 SBOM 作为输入并与多个咨询数据库关联的漏洞扫描程序
- **cyclonedx-python-lib**：用于以编程方式创建、解析和验证 CycloneDX SBOM 的 Python 库
- **lib4sbom**：用于解析 SPDX 和 CycloneDX 格式 SBOM 的 Python 库
- **nvdlib**：NVD 2.0 API 的 Python 包装器，支持具有速率限制管理的 CVE 和 CPE 查询
- **OWASP Dependency-Track**：持续 SBOM 分析、漏洞跟踪和策略执行的平台

## 常见场景

### 场景：Log4Shell 披露后评估供应商软件

**背景**：Log4Shell (CVE-2021-44228) 披露后，安全团队需要确定哪些供应商提供的应用程序包含易受攻击的 log4j 版本。一些供应商已根据合同要求提供了 SBOM。

**方法**：
1. 收集所有供应商 SBOM（CycloneDX 或 SPDX JSON 格式）
2. 解析每个SBOM并搜索版本<2.17.1的log4j-core组件
3. 查询特定 CVE 的 NVD API（CVE-2021-44228、CVE-2021-45046、CVE-2021-45105）
4. 构建依赖关系图来识别哪些应用程序组件依赖于 log4j
5. 计算爆炸半径：暴露了多少服务和端点
6. 生成按风险和业务重要性排序的优先修复报告
7. 使用相同 SBOM 的 grype 扫描交叉验证结果

**陷阱**：
- 供应商 SBOM 可能不完整，缺少嵌入 log4j 的阴影/捆绑 JAR 文件
- SPDX 和 CycloneDX 版本差异可能会影响解析器兼容性
- 在没有 API 密钥的情况下扫描数百个组件时，NVD API 速率限制可能会减慢分析速度
- SBOM 中的 CPE 名称可能与 NVD 条目不完全匹配，需要模糊匹配
- 传递依赖项可能包括 log4j，即使它不是直接依赖项