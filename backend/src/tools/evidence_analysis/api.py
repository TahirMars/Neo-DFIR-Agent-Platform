"""
证据分析 API：解析结构化文件、白名单/基线/异常、时间线（与 artifact 协作）。

对外 API 统一为 `parse_evidence_*`、`filter_evidence_*`、`compare_evidence_*`、`detect_evidence_*`、`build_evidence_timeline`、`query_evidence_timeline`、`summarize_evidence_timeline`。
"""
import time
from typing import Any

from src.core.ids import generate_id
from src.tools.envelope import envelope_err, envelope_ok
from src.tools.evidence_analysis.parsers import MAX_FILE_SIZE, parse_structured_data_bytes
from src.tools.evidence_analysis.filters import (
    filter_whitelist,
    baseline_compare,
    detect_anomalies,
)
from src.tools.evidence_analysis.timeline import (
    build_timeline,
    query_timeline,
    timeline_summary,
)


def _get_artifact_data(session_id: str, artifact_id: str) -> dict | None:
    from src.tools.evidence.tools import session_artifacts_get

    r = session_artifacts_get(session_id, artifact_id)
    if not r.get("ok"):
        return None
    payload = r.get("data") or {}
    return payload.get("json")


def _save_artifact(session_id: str, _name: str, data: dict) -> str:
    """写入会话 artifact，返回新 artifact_id。_name 保留供调用方标注用途。"""
    from src.tools.evidence.tools import session_artifacts_put

    artifact_id = generate_id("art")
    session_artifacts_put(session_id, artifact_id, {"json": data})
    return artifact_id


def parse_evidence_structured(
    case_id: str,
    evidence_id: str,
    path: str,
    format: str = "auto",
    options: dict[str, Any] | None = None,
) -> dict:
    """
    解析证据包内的结构化数据文件（CSV/JSON/JSONL/TXT），返回 envelope。

    case_id 预留与案件级策略一致；当前实现以 evidence_id 解析磁盘上的解压目录。
    """
    t0 = time.perf_counter()
    try:
        from src.tools.evidence.tools import _resolve_evidence_dir, _sanitize_path

        base = _resolve_evidence_dir(evidence_id)
        if not base:
            return envelope_err(["证据包不存在"], int((time.perf_counter() - t0) * 1000))

        try:
            safe_inner = _sanitize_path(path)
        except ValueError as e:
            return envelope_err([str(e)], int((time.perf_counter() - t0) * 1000))

        target = (base / safe_inner).resolve()
        if not str(target).startswith(str(base.resolve())):
            return envelope_err(["路径越界"], int((time.perf_counter() - t0) * 1000))

        if not target.is_file():
            return envelope_err([f"文件不存在: {path}"], int((time.perf_counter() - t0) * 1000))

        size = target.stat().st_size
        if size > MAX_FILE_SIZE:
            return envelope_err(
                [f"文件过大: {size} > {MAX_FILE_SIZE}"],
                int((time.perf_counter() - t0) * 1000),
            )

        content = target.read_bytes()
        inner_key = path.replace("\\", "/")
        result = parse_structured_data_bytes(inner_key, content, format, options)

        return envelope_ok(result, int((time.perf_counter() - t0) * 1000))

    except ValueError as e:
        return envelope_err([str(e)], int((time.perf_counter() - t0) * 1000))
    except Exception as e:
        return envelope_err([f"解析失败: {e}"], int((time.perf_counter() - t0) * 1000))


def filter_evidence_whitelist(
    case_id: str,
    session_id: str,
    data_source: str,
    whitelist: str,
    filter_fields: list[str],
) -> dict:
    """白名单过滤。data_source 为 artifact_id 或 \"evidence_id:path\"。"""
    t0 = time.perf_counter()
    try:
        if ":" in data_source:
            evidence_id, path = data_source.split(":", 1)
            parse_result = parse_evidence_structured(case_id, evidence_id, path)
            if not parse_result.get("ok"):
                return parse_result
            data = parse_result["data"]["data"]

            if "rows" in data:
                items = data["rows"]
            elif "data" in data and isinstance(data["data"], list):
                items = data["data"]
            else:
                return envelope_err(["无法提取数据项"], int((time.perf_counter() - t0) * 1000))
        else:
            artifact_data = _get_artifact_data(session_id, data_source)
            if not artifact_data:
                return envelope_err(["artifact 不存在"], int((time.perf_counter() - t0) * 1000))

            if "rows" in artifact_data:
                items = artifact_data["rows"]
            elif "data" in artifact_data:
                items = artifact_data["data"]
            else:
                items = [artifact_data]

        result = filter_whitelist(items, whitelist, filter_fields)

        return envelope_ok(result, int((time.perf_counter() - t0) * 1000))

    except Exception as e:
        return envelope_err([f"白名单过滤失败: {e}"], int((time.perf_counter() - t0) * 1000))


def compare_evidence_baseline(
    case_id: str,
    session_id: str,
    current_data: str,
    baseline_data: str,
    compare_fields: list[str],
    compare_mode: str = "diff",
) -> dict:
    """基线对比。current_data / baseline_data 为 artifact_id 或预定义基线名。"""
    t0 = time.perf_counter()
    try:
        current_artifact = _get_artifact_data(session_id, current_data)
        if not current_artifact:
            return envelope_err(["当前数据不存在"], int((time.perf_counter() - t0) * 1000))

        current_items = current_artifact.get("rows", current_artifact.get("data", []))
        if not isinstance(current_items, list):
            current_items = [current_items]

        if baseline_data.startswith("windows_") or baseline_data.startswith("common_"):
            from src.tools.evidence_analysis.whitelists import get_whitelist

            baseline_items = get_whitelist(baseline_data)
        else:
            baseline_artifact = _get_artifact_data(session_id, baseline_data)
            if not baseline_artifact:
                return envelope_err(["基线数据不存在"], int((time.perf_counter() - t0) * 1000))

            baseline_items = baseline_artifact.get("rows", baseline_artifact.get("data", []))
            if not isinstance(baseline_items, list):
                baseline_items = [baseline_items]

        result = baseline_compare(current_items, baseline_items, compare_fields, compare_mode)

        return envelope_ok(result, int((time.perf_counter() - t0) * 1000))

    except Exception as e:
        return envelope_err([f"基线对比失败: {e}"], int((time.perf_counter() - t0) * 1000))


def detect_evidence_anomalies(
    case_id: str,
    session_id: str,
    data_source: str,
    detection_rules: list[dict],
) -> dict:
    """异常检测。data_source 为 artifact_id。"""
    t0 = time.perf_counter()
    try:
        artifact_data = _get_artifact_data(session_id, data_source)
        if not artifact_data:
            return envelope_err(["数据不存在"], int((time.perf_counter() - t0) * 1000))

        items = artifact_data.get("rows", artifact_data.get("data", []))
        if not isinstance(items, list):
            items = [items]

        result = detect_anomalies(items, detection_rules)

        return envelope_ok(result, int((time.perf_counter() - t0) * 1000))

    except Exception as e:
        return envelope_err([f"异常检测失败: {e}"], int((time.perf_counter() - t0) * 1000))


def build_evidence_timeline(
    case_id: str,
    session_id: str,
    data_sources: list[dict],
    time_field: str = "timestamp",
    time_format: str = "auto",
) -> dict:
    """构建统一时间线并写入 artifact。"""
    t0 = time.perf_counter()
    try:
        sources_data = []
        for ds in data_sources:
            artifact_id = ds.get("artifact_id")
            artifact_data = _get_artifact_data(session_id, artifact_id)
            if not artifact_data:
                continue

            items = artifact_data.get("rows", artifact_data.get("data", []))
            if not isinstance(items, list):
                items = [items]

            sources_data.append(
                {
                    "source": ds.get("source_label", "Unknown"),
                    "data": items,
                    "time_field": ds.get("time_field", time_field),
                    "time_format": ds.get("time_format", time_format),
                    "event_type_field": ds.get("event_type_field"),
                }
            )

        result = build_timeline(sources_data, time_field, time_format)

        timeline_artifact_id = _save_artifact(session_id, "timeline", result)

        result["artifact_id"] = timeline_artifact_id

        return envelope_ok(result, int((time.perf_counter() - t0) * 1000))

    except Exception as e:
        return envelope_err([f"构建时间线失败: {e}"], int((time.perf_counter() - t0) * 1000))


def query_evidence_timeline(
    case_id: str,
    session_id: str,
    timeline_artifact_id: str,
    filters: dict | None = None,
) -> dict:
    """查询时间线 artifact。"""
    t0 = time.perf_counter()
    try:
        timeline_data = _get_artifact_data(session_id, timeline_artifact_id)
        if not timeline_data:
            return envelope_err(["时间线不存在"], int((time.perf_counter() - t0) * 1000))

        timeline_events = timeline_data.get("timeline", [])

        result = query_timeline(timeline_events, filters)

        return envelope_ok(result, int((time.perf_counter() - t0) * 1000))

    except Exception as e:
        return envelope_err([f"查询时间线失败: {e}"], int((time.perf_counter() - t0) * 1000))


def summarize_evidence_timeline(
    case_id: str,
    session_id: str,
    timeline_artifact_id: str,
    bucket_size: str = "1hour",
) -> dict:
    """时间线汇总统计。"""
    t0 = time.perf_counter()
    try:
        timeline_data = _get_artifact_data(session_id, timeline_artifact_id)
        if not timeline_data:
            return envelope_err(["时间线不存在"], int((time.perf_counter() - t0) * 1000))

        timeline_events = timeline_data.get("timeline", [])

        result = timeline_summary(timeline_events, bucket_size)

        return envelope_ok(result, int((time.perf_counter() - t0) * 1000))

    except Exception as e:
        return envelope_err([f"时间线汇总失败: {e}"], int((time.perf_counter() - t0) * 1000))
