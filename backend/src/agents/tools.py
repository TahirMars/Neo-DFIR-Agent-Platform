"""
LangGraph 工具工厂：为各智能体创建绑定上下文的 @tool 工具集。

工具分配策略：
- Supervisor  : 无工具（直接调用 Python 函数进行证据分类与任务规划）
- Forensic    : `create_evidence_analysis_tools`（ls / 按行或结构化读取 / grep / glob + 工作区 + 情报），已合并原 list/read/parse 为少量工具
- Sample      : 样本静态/动态分析 + IOC 情报查询
- Report      : 证据摘要汇总 + 案件记忆写回 + 可选 load_skill
- Chat        : 通用对话 + 威胁情报查询
"""
import json
from typing import Any

from langchain_core.tools import tool

from src.agents.middleware.memory import append_case_memory, extract_case_memory_section, load_case_memory
from src.core.config import get_settings
from src.core.hitl import (
    HITL_ENABLED,
    HITL_REQUIRED_TOOLS,
    check_approval,
    consume_approval,
    store_pending,
)
from src.tools.evidence.tools import (
    classify_evidence_files,
    evidence_glob,
    evidence_grep,
    evidence_ls,
    evidence_read as evidence_read_raw,
    get_evidence_manifest,
    workspace_read as workspace_read_raw,
    workspace_write as workspace_write_raw,
)
from src.tools.result_eviction import evict_large_result, evict_large_result_from_dict
from src.tools.sample_analysis.tools import static_analyze, dynamic_analyze
from src.tools.threat_intel.tools import lookup_iocs
from src.skills.skill_tools import make_load_skill_tool


def _optional_load_skill_tools(case_id: str, session_id: str) -> list:
    if not get_settings().skills_enabled or not get_settings().skills_load_tool_enabled:
        return []
    return [make_load_skill_tool(case_id, session_id)]


# 工具返回中附带章节快照时的最大字符数（避免单次工具结果撑爆上下文）
CASE_MEMORY_TOOL_SNIPPET_MAX_CHARS = 8000


def _make_case_memory_update_tool(case_id: str, session_id: str):
    """绑定 case/session 的 `case_memory_update` 工具（取证 / 样本 / 报告共用）。"""

    @tool
    def case_memory_update(section: str, content: str) -> str:
        """更新案件级长期记忆（跨 Session 共享）。发现重要 IOC、定性结论、分析进展时调用。
        章节名建议：`已确认 IOC`、`分析进展`、`待验证假设`、`案件概要`。

        Args:
            section: 章节名
            content: 要追加的简短 Markdown 要点（勿整篇粘贴报告）
        """
        r = append_case_memory(case_id, section, content, session_id)
        if not r.get("ok"):
            return r.get("error", "未知错误")
        fresh = load_case_memory(case_id) if (case_id or "").strip() else ""
        snippet = extract_case_memory_section(fresh, section) or fresh
        if len(snippet) > CASE_MEMORY_TOOL_SNIPPET_MAX_CHARS:
            snippet = snippet[:CASE_MEMORY_TOOL_SNIPPET_MAX_CHARS] + "\n\n...(本段过长已截断；完整内容见 workspace 下 .case_memory.md)"
        return (
            f"已追加至案件记忆章节「{section}」。以下为该章节当前完整内容（含历史条目），供你核对：\n\n"
            f"{snippet}"
        )

    return case_memory_update


def _format_ti_result(r: dict[str, Any]) -> str:
    """将丰富的威胁情报查询结果格式化为 Markdown 文本。"""
    parts: list[str] = []

    parts.append(f"**IOC**: `{r.get('value', '?')}` ({r.get('type', '?')})")
    parts.append(f"**判定**: {r.get('verdict', 'unknown')} | **置信度**: {r.get('confidence', 0):.2f}")
    if r.get("sources"):
        parts.append(f"**来源**: {' / '.join(r['sources'])}")

    if r.get("labels"):
        parts.append(f"**威胁标签**: {', '.join(r['labels'])}")
    if r.get("tags"):
        parts.append(f"**标签**: {', '.join(r['tags'])}")
    if r.get("description"):
        parts.append(f"**描述**: {r['description']}")
    if r.get("first_found_time"):
        parts.append(f"**首次发现**: {r['first_found_time']}")
    if r.get("update_time"):
        parts.append(f"**情报更新**: {r['update_time']}")

    geo = r.get("geo") or {}
    if geo:
        geo_parts = [f"{k}: {v}" for k, v in geo.items() if v]
        if geo_parts:
            parts.append(f"**地理位置**: {' | '.join(geo_parts)}")

    vt_stats = r.get("vt_stats") or {}
    if vt_stats:
        stats_str = " / ".join(f"{k}: {v}" for k, v in vt_stats.items())
        parts.append(f"**VT 引擎统计**: {stats_str}")

    related = r.get("related_files") or []
    if related:
        parts.append(f"**关联样本** ({len(related)} 个):")
        for f in related[:10]:
            if isinstance(f, dict):
                parts.append(f"  - {f.get('sha256', f.get('md5', '?'))} ({f.get('virus_name', '?')})")
            else:
                parts.append(f"  - {f}")

    file_info = r.get("file_info") or {}
    if file_info:
        fi_parts = [f"{k}: {v}" for k, v in file_info.items() if v]
        if fi_parts:
            parts.append(f"**文件详情**: {' | '.join(fi_parts[:8])}")

    da = r.get("dynamic_analysis") or {}
    if da:
        parts.append(f"**动态分析**: {json.dumps(da, ensure_ascii=False)[:500]}")

    nb = r.get("network_behavior") or {}
    if nb:
        parts.append(f"**网络行为**: {json.dumps(nb, ensure_ascii=False)[:500]}")

    vt_details = r.get("vt_details") or {}
    if vt_details:
        detail_keys = ["reputation", "registrar", "last_https_certificate_date",
                       "last_dns_records_date", "creation_date", "whois"]
        shown = {k: vt_details[k] for k in detail_keys if k in vt_details}
        if shown:
            parts.append(f"**VT 扩展信息**: {json.dumps(shown, ensure_ascii=False)[:400]}")

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Forensic Agent 工具集
# ---------------------------------------------------------------------------

def create_evidence_analysis_tools(
    case_id: str,
    evidence_ids: list[str],
    session_id: str,
    log_files: list[dict[str, Any]],
) -> list:
    """创建取证/日志分析智能体的工具集：ls、grep、glob、按行读/结构化预览、工作区、情报。"""

    allowed_log_paths = {str(f.get("path", "")) for f in log_files if f.get("path")}

    @tool
    def evidence_ls_tool(
        evidence_id: str,
        path_prefix: str = "",
        only_classified_logs: bool = False,
    ) -> str:
        """列出证据包内文件（ls）。可用 path_prefix 缩小范围；only_classified_logs=True 时仅显示主管分类为日志/文本的路径（替代旧 list_log_files）。

        Args:
            evidence_id: 证据包 ID
            path_prefix: 可选，路径前缀过滤，如 uploads/logs/
            only_classified_logs: 为 True 时只列出本轮已分类为「日志/文本」的文件路径
        """
        if only_classified_logs and not log_files:
            return "当前无已分类的日志/文本文件（主管分类结果为空）。"
        r = evidence_ls(evidence_id, path_prefix)
        if not r.get("ok"):
            return r.get("error", "未知错误")
        files = r.get("files", [])
        if only_classified_logs:
            files = [f for f in files if f.get("path") in allowed_log_paths]
        if not files:
            return "无匹配文件"
        lines = [f"- {f['path']} ({f.get('ext', '?')}, {round(f.get('size', 0) / 1024, 1)} KB)" for f in files[:50]]
        if len(files) > 50:
            lines.append(f"... 共 {len(files)} 个文件")
        return "\n".join(lines)

    @tool
    def evidence_read_tool(
        evidence_id: str,
        inner_path: str,
        offset: int = 0,
        limit: int = 100,
        structured: bool = False,
    ) -> str:
        """读取证据文件：默认按行分页（适合大文本日志）；structured=True 时对 CSV/JSON/JSONL 等做结构化摘要（替代旧 parse_structured_log）。

        Args:
            evidence_id: 证据包 ID
            inner_path: 文件在证据包内的路径
            offset: 按行读取时的起始行号（0-based）；structured=True 时忽略
            limit: 按行读取时的行数；小文件可读满时可适当增大
            structured: 为 True 时返回行列统计与预览（大结果可能卸载到 workspace）
        """
        if structured:
            from src.tools.evidence_analysis.api import parse_evidence_structured

            result = parse_evidence_structured(
                case_id, evidence_id, inner_path, format="auto", options={"max_rows": 50},
            )
            if not result.get("ok"):
                return f"无法结构化解析: {inner_path}"
            data = result["data"]
            parsed = data.get("data") or data.get("parsed_data", {})
            meta = data.get("metadata", {})
            total_hint = (
                parsed.get("total_rows")
                or parsed.get("total_items")
                or parsed.get("total_lines")
                or meta.get("total_rows")
            )
            summary_parts = [
                f"文件: {inner_path}",
                f"格式: {data.get('format', '?')}",
                f"总行数: {total_hint if total_hint is not None else '?'}",
            ]
            columns = parsed.get("columns") or parsed.get("headers")
            if columns:
                summary_parts.append(f"列: {', '.join(str(c) for c in columns)}")
            rows = parsed.get("rows") or parsed.get("data", [])
            if rows:
                preview = json.dumps(rows[:20], ensure_ascii=False, indent=1)
                if len(preview) > 8000:
                    preview = preview[:8000] + "\n... (预览已截断)"
                summary_parts.append(f"数据预览 (前 {min(len(rows), 20)} 行):\n{preview}")
            raw = "\n".join(summary_parts)
            return evict_large_result(raw, case_id, session_id, "evidence_read_tool")

        r = evidence_read_raw(evidence_id, inner_path, offset=offset, limit=limit)
        if not r.get("ok"):
            return r.get("error", "未知错误")
        content = r.get("content", "")
        total = r.get("total_lines", 0)
        return f"文件: {inner_path} | 总行数: {total} | 本段: 行 {offset}-{offset + len(content.splitlines())}\n\n{content}"

    @tool
    def evidence_grep_tool(evidence_id: str, pattern: str, path_filter: str = "") -> str:
        """在证据包内的文本文件中搜索关键字（字面匹配）。

        Args:
            evidence_id: 证据包 ID
            pattern: 要搜索的字符串
            path_filter: 可选，路径前缀过滤
        """
        r = evidence_grep(evidence_id, pattern, path_filter=path_filter, max_matches=50)
        if not r.get("ok"):
            return r.get("error", "未知错误")
        matches = r.get("matches", [])
        if not matches:
            return f"未找到包含 '{pattern}' 的匹配"
        lines = [f"[{m['file']}:{m['line_num']}] {m['content']}" for m in matches]
        if r.get("truncated"):
            lines.append("... (匹配已截断)")
        return "\n".join(lines)

    @tool
    def evidence_glob_tool(evidence_id: str, pattern: str) -> str:
        """按 glob 模式匹配证据包内文件名，如 *.log, uploads/**/*.csv。

        Args:
            evidence_id: 证据包 ID
            pattern: glob 模式
        """
        r = evidence_glob(evidence_id, pattern)
        if not r.get("ok"):
            return r.get("error", "未知错误")
        files = r.get("files", [])
        if not files:
            return f"无匹配文件: {pattern}"
        return "\n".join(f"- {f['path']} ({round(f.get('size', 0) / 1024, 1)} KB)" for f in files[:30])

    @tool
    def workspace_read_tool(rel_path: str) -> str:
        """读取工作区文件。用于读取完整历史(conversation_history.md)、工具大结果(tool_results/*)等。
        若某工具返回 `[输出过大已卸载]`，请用此处给出的相对路径（如 tool_results/xxx.txt）分段读取。

        Args:
            rel_path: 相对路径，如 conversation_history.md 或 tool_results/xxx.txt
        """
        r = workspace_read_raw(case_id, session_id, rel_path)
        if not r.get("ok"):
            return r.get("error", "未知错误")
        content = r.get("content", "")
        if r.get("truncated"):
            content += "\n\n... (文件过长已截断，可分段读取)"
        return content

    @tool
    def workspace_write_tool(rel_path: str, content: str) -> str:
        """写入工作区文件，保存分析笔记、中间结果等。

        Args:
            rel_path: 相对路径，如 analysis_notes.md
            content: 文件内容
        """
        r = workspace_write_raw(case_id, session_id, rel_path, content)
        if not r.get("ok"):
            return r.get("error", "未知错误")
        return f"已写入: {rel_path}"

    case_memory_update = _make_case_memory_update_tool(case_id, session_id)

    @tool
    def get_evidence_info(evidence_id: str) -> str:
        """获取指定证据包的清单信息（文件列表、原始文件名、SHA256等）。

        Args:
            evidence_id: 证据包 ID
        """
        manifest = get_evidence_manifest(evidence_id)
        if not manifest:
            return f"未找到证据包 {evidence_id}"
        info = {
            "evidence_id": manifest.get("evidence_id"),
            "original_filename": manifest.get("original_filename"),
            "sha256": manifest.get("sha256"),
            "file_count": len(manifest.get("files", [])),
        }
        return json.dumps(info, ensure_ascii=False, indent=2)

    @tool
    def query_threat_intel(ioc_type: str, ioc_value: str) -> str:
        """查询单条 IOC（威胁指标）的完整威胁情报，支持 sha256/md5/ip/domain/url。
        返回判定结果、威胁标签、地理位置、关联样本、VT 引擎统计等丰富信息。
        在日志分析过程中发现可疑 IP、域名、哈希等时调用此工具进行情报研判。
        大结果会自动卸载到 workspace，可用 workspace_read 读取完整内容。

        Args:
            ioc_type: IOC 类型，可选 sha256, md5, ip, domain, url
            ioc_value: IOC 值，如 IP 地址、域名、文件哈希等
        """
        result = lookup_iocs(case_id, session_id, [{"type": ioc_type, "value": ioc_value}])
        if result.get("ok") and result["data"]["results"]:
            formatted = _format_ti_result(result["data"]["results"][0])
            return evict_large_result(formatted, case_id, session_id, "query_threat_intel")
        errors = result.get("errors", ["查询失败"])
        return f"情报查询失败: {'; '.join(errors)}"

    tools = [
        evidence_ls_tool,
        evidence_read_tool,
        evidence_grep_tool,
        evidence_glob_tool,
        workspace_read_tool,
        workspace_write_tool,
        case_memory_update,
        get_evidence_info,
        query_threat_intel,
    ]
    tools.extend(_optional_load_skill_tools(case_id, session_id))
    return tools


def create_forensic_tools(
    case_id: str,
    evidence_ids: list[str],
    session_id: str,
    log_files: list[dict[str, Any]],
) -> list:
    """兼容别名：等同于 create_evidence_analysis_tools。"""
    return create_evidence_analysis_tools(case_id, evidence_ids, session_id, log_files)


# ---------------------------------------------------------------------------
# Sample Agent 工具集
# ---------------------------------------------------------------------------

def create_sample_tools(
    case_id: str,
    evidence_ids: list[str],
    session_id: str,
    binary_files: list[dict[str, Any]],
) -> list:
    """创建样本分析智能体的工具集（绑定上下文）。"""

    @tool
    def list_binary_files() -> str:
        """列出当前证据包中所有二进制/样本文件，返回文件路径、大小、扩展名等信息。"""
        if not binary_files:
            return "当前证据包中无二进制/样本文件。"
        lines = []
        for f in binary_files:
            size_kb = round(f.get("size", 0) / 1024, 1)
            lines.append(f"- {f['path']}  (扩展名: {f.get('ext', '?')}, 大小: {size_kb} KB)")
        return "\n".join(lines)

    @tool
    def run_static_analysis(sample_path: str) -> str:
        """对指定样本文件执行静态分析（哈希提取、字符串扫描、YARA 匹配等）。
        大结果会自动卸载到 workspace，可用 workspace_read 读取完整内容。

        Args:
            sample_path: 样本文件在证据包内的路径
        """
        result = static_analyze(case_id, session_id, sample_path)
        if result.get("ok"):
            return evict_large_result_from_dict(
                result["data"], case_id, session_id, "run_static_analysis"
            )
        errors = result.get("errors", ["未知错误"])
        return f"静态分析失败: {'; '.join(errors)}"

    @tool
    def run_dynamic_analysis(sample_path: str) -> str:
        """对指定样本文件执行动态分析（沙箱运行、行为捕获）。此操作需人工审批。
        大结果会自动卸载到 workspace，可用 workspace_read 读取完整内容。

        Args:
            sample_path: 样本文件在证据包内的路径
        """
        args = {"sample_path": sample_path}
        if HITL_ENABLED and "run_dynamic_analysis" in HITL_REQUIRED_TOOLS:
            if not check_approval(session_id, "run_dynamic_analysis", args):
                approval_id = store_pending(session_id, "run_dynamic_analysis", args)
                try:
                    from langgraph.config import get_stream_writer
                    writer = get_stream_writer()
                    writer({"type": "tool_approval_required", "approval_id": approval_id, "tool": "run_dynamic_analysis", "args": args})
                except Exception:
                    pass
                return (
                    f"【需人工审批】动态分析 {sample_path} 需在前端批准后继续。"
                    f"请用户点击批准后发送「继续」重试。approval_id={approval_id}"
                )
        result = dynamic_analyze(case_id, session_id, sample_path)
        if result.get("ok"):
            consume_approval(session_id, "run_dynamic_analysis", args)
            return evict_large_result_from_dict(
                result["data"], case_id, session_id, "run_dynamic_analysis"
            )
        errors = result.get("errors", ["未知错误"])
        return f"动态分析失败: {'; '.join(errors)}"

    @tool
    def read_binary_file_metadata(file_path: str) -> str:
        """读取二进制文件的基础元数据（大小、路径），不读取二进制内容。

        Args:
            file_path: 文件在证据包内的路径
        """
        for f in binary_files:
            if f.get("path") == file_path:
                return json.dumps(f, ensure_ascii=False, indent=2)
        return f"未找到文件: {file_path}"

    @tool
    def query_hash_intel(hash_type: str, hash_value: str) -> str:
        """查询文件哈希的完整威胁情报，判定样本是否为已知恶意软件。
        返回判定结果、家族标签、文件详情、动态分析、网络行为、VT 引擎统计等丰富信息。
        在静态分析提取哈希后调用此工具进行情报碰撞。
        大结果会自动卸载到 workspace，可用 workspace_read 读取完整内容。

        Args:
            hash_type: 哈希类型，sha256 或 md5
            hash_value: 哈希值
        """
        if hash_type not in ("sha256", "md5"):
            return "仅支持 sha256 或 md5 类型"
        result = lookup_iocs(case_id, session_id, [{"type": hash_type, "value": hash_value}])
        if result.get("ok") and result["data"]["results"]:
            formatted = _format_ti_result(result["data"]["results"][0])
            return evict_large_result(formatted, case_id, session_id, "query_hash_intel")
        errors = result.get("errors", ["查询失败"])
        return f"情报查询失败: {'; '.join(errors)}"

    @tool
    def evidence_glob_tool(evidence_id: str, pattern: str) -> str:
        """按 glob 模式匹配证据包内文件名，如 *.exe, *.dll。

        Args:
            evidence_id: 证据包 ID
            pattern: glob 模式
        """
        r = evidence_glob(evidence_id, pattern)
        if not r.get("ok"):
            return r.get("error", "未知错误")
        files = r.get("files", [])
        if not files:
            return f"无匹配文件: {pattern}"
        return "\n".join(f"- {f['path']} ({round(f.get('size', 0) / 1024, 1)} KB)" for f in files[:30])

    @tool
    def workspace_read_tool(rel_path: str) -> str:
        """读取工作区文件（完整历史、工具大结果等）。
        若某工具返回 `[输出过大已卸载]`，请用返回中的相对路径调用本工具读取全文。

        Args:
            rel_path: 相对路径，如 conversation_history.md 或 tool_results/xxx.txt
        """
        r = workspace_read_raw(case_id, session_id, rel_path)
        if not r.get("ok"):
            return r.get("error", "未知错误")
        content = r.get("content", "")
        if r.get("truncated"):
            content += "\n\n... (文件过长已截断)"
        return content

    @tool
    def workspace_write_tool(rel_path: str, content: str) -> str:
        """写入工作区文件，保存分析笔记。

        Args:
            rel_path: 相对路径
            content: 文件内容
        """
        r = workspace_write_raw(case_id, session_id, rel_path, content)
        if not r.get("ok"):
            return r.get("error", "未知错误")
        return f"已写入: {rel_path}"

    case_memory_update = _make_case_memory_update_tool(case_id, session_id)

    tools = [
        list_binary_files,
        run_static_analysis,
        run_dynamic_analysis,
        read_binary_file_metadata,
        query_hash_intel,
        evidence_glob_tool,
        workspace_read_tool,
        workspace_write_tool,
        case_memory_update,
    ]
    tools.extend(_optional_load_skill_tools(case_id, session_id))
    return tools


# ---------------------------------------------------------------------------
# Report Agent 工具集
# ---------------------------------------------------------------------------

def create_report_tools(
    case_id: str,
    evidence_ids: list[str],
    session_id: str,
) -> list:
    """创建报告生成智能体的工具集。"""

    @tool
    def get_evidence_summary() -> str:
        """获取所有证据包的摘要信息（文件数量、分类等）。"""
        summaries = []
        for eid in evidence_ids:
            manifest = get_evidence_manifest(eid)
            if manifest:
                classification = classify_evidence_files(eid)
                summaries.append(
                    f"证据 {eid}: {manifest.get('original_filename', '?')}, "
                    f"日志 {len(classification.get('log', []))} 个, "
                    f"样本 {len(classification.get('binary', []))} 个, "
                    f"其他 {len(classification.get('other', []))} 个"
                )
        return "\n".join(summaries) if summaries else "无证据信息"

    case_memory_update = _make_case_memory_update_tool(case_id, session_id)

    tools = [get_evidence_summary, case_memory_update]
    tools.extend(_optional_load_skill_tools(case_id, session_id))
    return tools


# ---------------------------------------------------------------------------
# Chat Agent 工具集（通用对话 + 情报查询）
# ---------------------------------------------------------------------------

def create_chat_tools(
    case_id: str = "",
    session_id: str = "",
) -> list:
    """创建通用聊天智能体的工具集（威胁情报查询）。"""

    @tool
    def lookup_threat_intel(ioc_type: str, ioc_value: str) -> str:
        """查询 IOC（威胁指标）的完整威胁情报。
        支持查询类型：sha256, md5, ip, domain, url。
        返回判定结果、威胁标签、地理位置、关联样本、VT 引擎统计、动态分析等丰富信息。
        大结果会自动卸载到 workspace，可用 workspace_read 读取完整内容。

        Args:
            ioc_type: IOC 类型 (sha256/md5/ip/domain/url)
            ioc_value: IOC 值
        """
        result = lookup_iocs(case_id, session_id, [{"type": ioc_type, "value": ioc_value}])
        if result.get("ok") and result["data"]["results"]:
            formatted = _format_ti_result(result["data"]["results"][0])
            return evict_large_result(formatted, case_id, session_id, "lookup_threat_intel")
        errors = result.get("errors", ["查询失败"])
        return f"情报查询失败: {'; '.join(errors)}"

    @tool
    def workspace_read_tool(rel_path: str) -> str:
        """读取当前会话工作区文件（对话历史、工具大结果、分析笔记等）。
        若某工具返回 `[输出过大已卸载]`，请用返回中的相对路径调用本工具读取全文。

        Args:
            rel_path: 相对路径，如 conversation_history.md 或 tool_results/xxx.txt
        """
        r = workspace_read_raw(case_id, session_id, rel_path)
        if not r.get("ok"):
            return r.get("error", "未知错误")
        content = r.get("content", "")
        if r.get("truncated"):
            content += "\n\n... (文件过长已截断)"
        return content

    tools = [
        lookup_threat_intel,
        workspace_read_tool,
    ]
    tools.extend(_optional_load_skill_tools(case_id, session_id))
    return tools
