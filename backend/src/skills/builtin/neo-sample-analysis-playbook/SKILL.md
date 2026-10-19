---
id: neo-sample-analysis-playbook
name: 样本分析总流程（Neo 工具映射）
description: 将 sample_analysis 项目中的静动态分析顺序与 triage 习惯映射到 Neo 样本智能体工具：清单、静态、情报、动态（审批）与工作区卸载阅读。
neo_agents:
  - sample
---

## 使用时机

- 证据包中存在待分析的二进制/样本，需系统化产出结论与 IOC。
- 用户曾使用独立 MCP（malware-static / malware-dynamic）路径，需在 Neo 内用**证据内路径**完成等价流程。

## 本技能与「工具」的关系（重要）

- **技能本身不执行代码、也不直接调 API**：`SKILL.md` 只是写入样本分析智能体的**系统提示片段**，与 `SAMPLE_ANALYSIS_PROMPT` 拼接后由同一轮对话里的 **LLM + ReAct** 使用。
- **真正触发后端逻辑的是 LangChain 已注册的工具**（与上表名称一致，如 `run_static_analysis`）。模型必须通过 **function calling / 工具调用** 调用它们，才能得到哈希、静态报告等；不要只用自然语言描述「已分析」而未实际调工具。
- 当会话勾选本 `skill_id`（或路由自动挂载）且任务走到 **sample 智能体** 时，你会同时看到：工具列表（含参数说明）+ 本技能正文，按上表逐步调用即可。

## Neo 工具 ↔ 原 MCP 思路

| 目标 | Neo 工具 | 说明 |
|------|-----------|------|
| 列样本 | `list_binary_files`、`evidence_glob_tool` | 路径为证据包内相对/展示路径，勿假设宿主机 `D:\samples` 或 `Z:\`。 |
| 类型/大小等元数据 | `read_binary_file_metadata` | 不读二进制正文。 |
| 哈希、字符串、YARA 等静态聚合 | `run_static_analysis(sample_path)` | 对应原 `get_file_hash` + 多类静态检查的综合入口；从中提取 MD5/SHA256 再查情报。 |
| 威胁情报 | `query_hash_intel(hash_type, hash_value)` | 对应原 `query_virustotal`；仅支持 `sha256` / `md5`。 |
| 沙箱/行为 | `run_dynamic_analysis(sample_path)` | 可能需人工审批；对应原 Sysmon/Speakeasy/Frida 等一体化动态能力（由后端实现封装）。 |
| 大结果 | `workspace_read_tool` | 工具若提示已卸载到 workspace，用返回的相对路径读取全文。 |
| 持久化发现 | `case_memory_update`、`workspace_write_tool` | 家族、关键 API 链、C2 等写入案件记忆或分析笔记。 |

## 推荐工作流

1. `list_binary_files`（必要时 `evidence_glob_tool`）确认主样本与附属文件（安装包、释放 DLL 等）。
2. `read_binary_file_metadata` 确认大小；过大时仍可先跑静态，避免一次性读全文。
3. `run_static_analysis` → 从返回中提取哈希与可疑特征（导入、节名、熵等摘要）。
4. 对提取的 `md5` / `sha256` 调用 `query_hash_intel`。
5. 若需行为验证且环境允许，申请 `run_dynamic_analysis`；遇「需人工审批」时明确告知用户批准后再重试。
6. 结论按「样本标识 → 行为要点 → IOC → 置信度与局限」组织；证据引用静态/动态/情报返回中的字段，勿编造未出现的路径或哈希。

## 路径说明（与 sample_analysis 文档的差异）

原项目使用 `sample_root`、`path_alias`（如 `D:\samples` ↔ `Z:\`）与虚拟机复制。**在 Neo 中**一律使用证据清单中的 `sample_path` / `file_path`，与宿主机共享目录无必然对应关系。

## 代码与动态扩展

- 原 **malware-static / malware-dynamic / pyghidra_mcp** 源码在仓库 **`ref/sample_analysis/`**（见 `ref/sample_analysis/README_NEO.md`）。
- 后端已内置本地静态引擎（哈希、熵、字符串、简易 PE）；动态分析可在 `.env` 配置 **`SAMPLE_DYNAMIC_SUBPROCESS`**（命令前缀，进程 **stdout 为 JSON**，Neo 将样本绝对路径追加为最后一参数）。

## 注意

- 不要在未做静态与情报前仅依赖动态结论。
- 若静态结果为空或失败，在分析中写明失败原因与下一步（换样本路径、检查证据是否完整等）。
