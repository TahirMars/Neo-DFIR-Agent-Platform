"""
威胁情报工具实现，参考 ref/mcp-server/mcp-ti。
lookup_iocs：IOC 查询，支持 VirusTotal、可选深信服、白名单与缓存。
返回丰富的情报信息：verdict、labels、description、关联文件、地理位置、动态分析等。
"""
import asyncio
import json
import logging
import time
from typing import Any

from src.core.config import get_settings
from src.tools.envelope import envelope_err, envelope_ok
from src.tools.threat_intel import ti_cache
from src.tools.threat_intel import virustotal as vt
from src.tools.threat_intel import tisangfor as sangfor

logger = logging.getLogger(__name__)

IOC_TYPES = ("sha256", "md5", "ip", "domain", "url")

_VERDICT_ORDER = {"malicious": 3, "suspicious": 2, "unknown": 1, "benign": 0}


def _merge_verdict(v1: str, v2: str) -> str:
    """取较严重的 verdict。"""
    o1 = _VERDICT_ORDER.get(v1, 1)
    o2 = _VERDICT_ORDER.get(v2, 1)
    return max([(v1, o1), (v2, o2)], key=lambda x: x[1])[0]


async def _lookup_one(ioc_type: str, value: str) -> dict[str, Any]:
    """
    单条 IOC 查询：白名单 → 缓存 → VirusTotal + 深信服 → 合并丰富结果并写回缓存。

    返回结构:
        {
            "verdict": str,          # malicious|suspicious|unknown|benign
            "confidence": float,     # 0~1
            "sources": [str],        # 情报来源摘要
            "tags": [str],           # 聚合标签
            "labels": [str],         # 威胁分类标签
            "description": str,      # 威胁描述
            "first_found_time": str, # 首次发现时间
            "update_time": str,      # 情报更新时间
            "related_files": [...],  # 关联通信文件
            "geo": {...},            # IP 地理位置（仅 IP 类型）
            "file_info": {...},      # 文件详情（仅哈希类型）
            "dynamic_analysis": {},  # 沙箱动态分析（仅哈希类型）
            "network_behavior": {},  # 网络行为分析（仅哈希类型）
            "vt_stats": {},          # VT 引擎检测统计
            "vt_details": {},        # VT 完整属性
        }
    """
    settings = get_settings()

    # --- 白名单 ---
    whitelist = ti_cache.get_whitelist(settings.ti_whitelist_path)
    if value in whitelist:
        return _make_result(verdict="benign", confidence=1.0, sources=["whitelist"])

    # --- 缓存 ---
    cached = ti_cache.memory_get(ioc_type, value)
    if not cached and settings.ti_cache_path:
        cached = ti_cache.sqlite_get(settings.ti_cache_path, ioc_type, value)
    if cached:
        return cached

    # --- URL 暂不调用外部 API ---
    if ioc_type == "url":
        verdict, confidence = _mock_lookup(ioc_type, value)
        return _make_result(verdict=verdict, confidence=confidence, sources=["neo-mock-ti"])

    verdict = "unknown"
    confidence = 0.0
    sources: list[str] = []
    tags: list[str] = []
    labels: list[str] = []
    description = ""
    first_found_time = ""
    update_time = ""
    related_files: list[dict] = []
    geo: dict[str, Any] = {}
    file_info: dict[str, Any] = {}
    dynamic_analysis: dict[str, Any] = {}
    network_behavior: dict[str, Any] = {}
    vt_stats: dict[str, int] = {}
    vt_details: dict[str, Any] = {}

    # --- VirusTotal ---
    vt_key = settings.virustotal_api_key
    if vt_key:
        vt_res: dict[str, Any] | None = None
        if ioc_type == "domain" and vt.is_valid_domain(value):
            vt_res = await vt.query_domain(vt_key, value)
        elif ioc_type == "ip" and vt.is_valid_ip(value):
            vt_res = await vt.query_ip(vt_key, value)
        elif ioc_type == "sha256" and vt.is_valid_sha256(value):
            vt_res = await vt.query_file_hash(vt_key, value)
        elif ioc_type == "md5" and vt.is_valid_md5(value):
            vt_res = await vt.query_file_hash(vt_key, value)

        if vt_res and vt_res.get("verdict") != "unknown":
            verdict = _merge_verdict(verdict, vt_res["verdict"])
            confidence = max(confidence, vt_res["confidence"])
            sources.append(f"VirusTotal: {vt_res['summary']}")
            tags.extend(vt_res.get("tags") or [])
            vt_stats = vt_res.get("stats") or {}
            vt_details = vt_res.get("details") or {}
        elif vt_res and vt_res.get("summary"):
            sources.append(f"VirusTotal: {vt_res['summary']}")

    # --- 深信服 ---
    if settings.sangfor_cookie and settings.sangfor_csrf_token:
        try:
            sf_res: dict[str, Any] | None = None
            if ioc_type == "domain" and vt.is_valid_domain(value):
                sf_res = await sangfor.query_domain_sangfor(
                    settings.sangfor_cookie, settings.sangfor_csrf_token, value,
                )
            elif ioc_type == "ip" and vt.is_valid_ip(value):
                sf_res = await sangfor.query_ip_sangfor(
                    settings.sangfor_cookie, settings.sangfor_csrf_token, value,
                )
            elif ioc_type in ("sha256", "md5"):
                sf_res = await sangfor.query_hash_sangfor(
                    settings.sangfor_cookie, settings.sangfor_csrf_token, value,
                )

            if sf_res and sf_res.get("verdict") != "unknown":
                verdict = _merge_verdict(verdict, sf_res["verdict"])
                confidence = max(confidence, sf_res["confidence"])
                sources.append(f"Sangfor: {sf_res['summary']}")
                labels.extend(sf_res.get("labels") or [])
                description = description or sf_res.get("description", "")
                first_found_time = first_found_time or sf_res.get("first_found_time", "")
                update_time = update_time or sf_res.get("update_time", "")
                related_files.extend(sf_res.get("related_files") or [])
                if sf_res.get("geo"):
                    geo = sf_res["geo"]
                if sf_res.get("file_info"):
                    file_info = sf_res["file_info"]
                if sf_res.get("dynamic_analysis"):
                    dynamic_analysis = sf_res["dynamic_analysis"]
                if sf_res.get("network_behavior"):
                    network_behavior = sf_res["network_behavior"]
        except Exception as e:
            logger.warning("深信服 TI 查询异常: %s", e)

    # --- 无任何外部源时使用模拟 ---
    if not sources:
        verdict, confidence = _mock_lookup(ioc_type, value)
        sources = ["neo-mock-ti"]

    result = _make_result(
        verdict=verdict,
        confidence=confidence,
        sources=sources,
        tags=list(set(tags)),
        labels=list(set(labels)),
        description=description,
        first_found_time=first_found_time,
        update_time=update_time,
        related_files=related_files,
        geo=geo,
        file_info=file_info,
        dynamic_analysis=dynamic_analysis,
        network_behavior=network_behavior,
        vt_stats=vt_stats,
        vt_details=vt_details,
    )

    # --- 写回缓存 ---
    ti_cache.memory_set(ioc_type, value, result)
    if settings.ti_cache_path:
        ti_cache.sqlite_set(settings.ti_cache_path, ioc_type, value, result)

    return result


def _make_result(
    verdict: str = "unknown",
    confidence: float = 0.0,
    sources: list[str] | None = None,
    tags: list[str] | None = None,
    labels: list[str] | None = None,
    description: str = "",
    first_found_time: str = "",
    update_time: str = "",
    related_files: list[dict] | None = None,
    geo: dict[str, Any] | None = None,
    file_info: dict[str, Any] | None = None,
    dynamic_analysis: dict[str, Any] | None = None,
    network_behavior: dict[str, Any] | None = None,
    vt_stats: dict[str, int] | None = None,
    vt_details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """构建标准化的情报结果字典。"""
    return {
        "verdict": verdict,
        "confidence": confidence,
        "sources": sources or [],
        "tags": tags or [],
        "labels": labels or [],
        "description": description,
        "first_found_time": first_found_time,
        "update_time": update_time,
        "related_files": related_files or [],
        "geo": geo or {},
        "file_info": file_info or {},
        "dynamic_analysis": dynamic_analysis or {},
        "network_behavior": network_behavior or {},
        "vt_stats": vt_stats or {},
        "vt_details": vt_details or {},
    }


def _mock_lookup(ioc_type: str, value: str) -> tuple[str, float]:
    """模拟 TI 查询：无外部 API 或未命中时使用。"""
    if ioc_type == "ip" and value.startswith("192.0.2."):
        return "suspicious", 0.7
    if ioc_type == "domain" and ("malware" in value or "evil" in value):
        return "malicious", 0.85
    return "unknown", 0.0


# ---------------------------------------------------------------------------
# 公开 API
# ---------------------------------------------------------------------------

def lookup_iocs(
    case_id: str,
    session_id: str,
    iocs: list[dict[str, str]],
) -> dict[str, Any]:
    """
    查询 IOC 威胁情报。

    Args:
        iocs: [{"type": "sha256"|"md5"|"ip"|"domain"|"url", "value": str}]

    Returns:
        MCP Envelope，data.results 中每条包含 verdict、labels、description、
        关联文件、VT 检测统计等丰富情报。
    """
    t0 = time.perf_counter()
    try:
        if not iocs:
            return envelope_ok({"results": []}, int((time.perf_counter() - t0) * 1000))
        results = []
        for item in iocs:
            t = (item.get("type") or "").lower()
            v = (item.get("value") or "").strip()
            if t not in IOC_TYPES:
                return envelope_err(
                    [f"不支持的 IOC 类型: {t}，允许: {IOC_TYPES}"],
                    int((time.perf_counter() - t0) * 1000),
                )
            if not v:
                results.append(_make_result(sources=[]))
                results[-1]["type"] = t
                results[-1]["value"] = ""
                continue
            one = asyncio.run(_lookup_one(t, v))
            one["type"] = t
            one["value"] = v
            results.append(one)
        return envelope_ok(
            {"results": results},
            int((time.perf_counter() - t0) * 1000),
        )
    except Exception as e:
        return envelope_err(
            [f"lookup_iocs 失败: {e}"],
            int((time.perf_counter() - t0) * 1000),
        )
