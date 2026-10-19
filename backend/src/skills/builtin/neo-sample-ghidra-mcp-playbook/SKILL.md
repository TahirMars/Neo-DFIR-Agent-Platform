---
id: neo-sample-ghidra-mcp-playbook
name: Ghidra / pyghidra_mcp 逆向阶段（外部 MCP）
description: 对应 malware-reversing（pyghidra_mcp）的深度静态流程：元数据、导入导出、字符串、反编译与交叉引用；说明如何与 Neo 样本分析衔接。
neo_agents:
  - sample
---

## 使用时机

- 样本为 Native PE/ELF 等，需在 Ghidra 中做函数级分析；或用户已在 Neo 外启用 `malware-reversing` MCP。
- Neo 内置工具**不包含** Ghidra 反编译接口时，本技能指导分析师（或外部自动化）应完成的检查项及如何回填 Neo。

## 与 Neo 工具的关系

- 本技能**不替代** `run_static_analysis` / `query_hash_intel` 等：在 Neo 内仍应**先工具调用**完成证据侧静态与情报，再用本清单指导 Ghidra 侧工作或整理结论。
- 将 Ghidra 结论写回时，使用 `workspace_write_tool`、`case_memory_update`（名称与样本智能体注册的工具一致，须通过工具调用写入）。

## 推荐分析顺序（与 intermediate_notes Phase 2 一致）

1. **加载与元数据**  
   在 Ghidra 工程中打开样本；记录基址、入口点（`entry` / `DllMain` / `WinMain`）、架构、编译器线索、样本哈希（与 `run_static_analysis` / `query_hash_intel` 对齐）。

2. **入口与控制流**  
   从入口函数向下跟踪主分支；标注「参数驱动的分支」（如 `param_2 == 1` 才进入恶意路径）。

3. **导入表（IAT）**  
   列出网络、进程/线程、内存执行（如 `VirtualAlloc` + `PAGE_EXECUTE_READWRITE`、`CreateThread`）、持久化（注册表/服务）、反调试（`IsDebuggerPresent`、VEH）等 API；说明与行为假设的对应关系。

4. **字符串与资源**  
   检索 URL、IP、路径模板、注册表键、脚本片段；注意环境变量展开、硬编码路径伪装。

5. **关键函数**  
   对解密桩、加载器、shellcode 投递函数做反编译（原 MCP：`decompile_function`）；记录伪代码级证据（缓冲区长度、XOR/密钥流、末尾补丁如 `0xC3 ret`）。

6. **交叉引用**  
   对敏感 API 做 xref，缩小首恶函数集合（原 MCP 常见能力：`list_funcs` 过滤、`disasm` 等，依实际 MCP 为准）。

## 回填 Neo

- 将 **函数地址/名称、调用链摘要、关键伪代码片段（精简）** 写入 `workspace_write_tool` 或会话可见的笔记文件，便于报告智能体引用。
- 将 **稳定 IOC、家族标签、TTP 摘要** 写入 `case_memory_update`。
- 若计划动态验证，列出建议 Hook 的 API 或进程阶段，供 `run_dynamic_analysis` 结果对照。

## 局限

- Neo 子 Agent 若无法直接调用 pyghidra MCP，应明确告知用户：深度反编译结论需人工在 Ghidra 中完成或通过外部集成导入要点，避免虚构函数名与地址。
