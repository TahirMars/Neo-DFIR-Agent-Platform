"""
样本分析：静态（本地引擎 + 证据路径解析）、动态（可选外部子进程钩子或占位）。

移植说明：`ref/sample_analysis/` 含原 malware-static / malware-dynamic / pyghidra_mcp 源码；
`sysmon_filter.py`、`speakeasy_utils.py` 已纳入本包供处理 Sysmon / Speakeasy JSON。
"""
from __future__ import annotations

import json
import logging
import os
import shlex
import subprocess
import time
from typing import Any

from src.core.config import get_settings
from src.tools.envelope import envelope_err, envelope_ok
from src.tools.sample_analysis.resolve import resolve_sample_path
from src.tools.sample_analysis.static_engine import build_static_report

logger = logging.getLogger(__name__)


def static_analyze(
    case_id: str,
    session_id: str,
    sample_ref: str,
    temp_path: str | None = None,
) -> dict[str, Any]:
    """
    静态分析：解析证据内路径，计算哈希、熵、字符串、简易 PE 信息。
    temp_path 保留兼容，当前未使用（优先证据 manifest）。
    """
    _ = temp_path
    t0 = time.perf_counter()
    resolved = resolve_sample_path(case_id, session_id, sample_ref)
    if not resolved:
        return envelope_err(
            [f"未在案件/会话证据中找到样本: {sample_ref}（请使用 list_binary_files 中的 path）"],
            int((time.perf_counter() - t0) * 1000),
        )
    eid, abspath, inner = resolved
    try:
        report = build_static_report(abspath, evidence_id=eid, inner_path=inner)
    except OSError as e:
        return envelope_err([f"读取样本失败: {e}"], int((time.perf_counter() - t0) * 1000))
    return envelope_ok(
        {"report": report},
        int((time.perf_counter() - t0) * 1000),
    )


def dynamic_analyze(
    case_id: str,
    session_id: str,
    sample_ref: str,
    temp_path: str | None = None,
) -> dict[str, Any]:
    """
    动态分析：若配置 sample_dynamic_subprocess，则启动子进程并将样本绝对路径作为最后一参数；
    期望 stdout 为 JSON 对象。未配置时返回结构化占位说明。
    """
    _ = temp_path
    t0 = time.perf_counter()
    resolved = resolve_sample_path(case_id, session_id, sample_ref)
    if not resolved:
        return envelope_err(
            [f"未在案件/会话证据中找到样本: {sample_ref}"],
            int((time.perf_counter() - t0) * 1000),
        )
    eid, abspath, inner = resolved
    settings = get_settings()
    hook = (getattr(settings, "sample_dynamic_subprocess", None) or "").strip()
    if hook:
        parts = shlex.split(hook, posix=os.name != "nt")
        if not parts:
            return envelope_err(["SAMPLE_DYNAMIC_SUBPROCESS 解析为空"], int((time.perf_counter() - t0) * 1000))
        cmd = list(parts) + [str(abspath)]
        timeout = int(getattr(settings, "sample_dynamic_timeout_seconds", 600) or 600)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=max(1, timeout),
                encoding="utf-8",
                errors="replace",
            )
        except subprocess.TimeoutExpired:
            return envelope_err([f"动态分析超时（{timeout}s）"], int((time.perf_counter() - t0) * 1000))
        except OSError as e:
            return envelope_err([f"无法启动动态分析进程: {e}"], int((time.perf_counter() - t0) * 1000))

        raw = (proc.stdout or "").strip()
        err_tail = (proc.stderr or "")[-4000:]
        if proc.returncode != 0 and not raw:
            return envelope_err(
                [f"动态分析退出码 {proc.returncode}", err_tail or "无 stderr"],
                int((time.perf_counter() - t0) * 1000),
            )
        payload: dict[str, Any]
        try:
            payload = json.loads(raw) if raw else {}
            if not isinstance(payload, dict):
                payload = {"result": payload}
        except json.JSONDecodeError:
            payload = {"raw_stdout": raw[:50_000], "stderr_tail": err_tail}

        payload.setdefault("sample_ref", inner)
        payload.setdefault("evidence_id", eid)
        return envelope_ok(
            {"report": payload},
            int((time.perf_counter() - t0) * 1000),
        )

    report = {
        "sample_ref": inner,
        "evidence_id": eid,
        "sandbox_task_id": None,
        "behaviors": [],
        "network_iocs": [],
        "dropped_files": [],
        "disposition": (
            "未配置动态分析子进程。可在 .env 设置 SAMPLE_DYNAMIC_SUBPROCESS "
            "（命令 + 参数前缀，Neo 会将样本绝对路径追加为最后一参）；"
            "或使用 ref/sample_analysis/malware-dynamic 独立 MCP。"
        ),
        "evidence_refs": [eid],
    }
    return envelope_ok(
        {"report": report},
        int((time.perf_counter() - t0) * 1000),
    )
