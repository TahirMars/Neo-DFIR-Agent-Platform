"""
VirusTotal API v3 异步客户端（参考 ref/mcp-server/mcp-ti/virustotal.py）。
支持域名/IP/文件哈希查询，返回完整属性（标签、分类、注册信息、日期、引擎检测详情等）。
"""
from __future__ import annotations

import re
from typing import Any

import httpx

VT_BASE = "https://www.virustotal.com/api/v3/"

# 从完整响应中保留的有价值属性键（过滤掉冗长的 last_analysis_results 等）
_USEFUL_DOMAIN_KEYS = {
    "categories", "creation_date", "last_modification_date", "last_update_date",
    "registrar", "reputation", "tags", "total_votes", "whois",
    "popularity_ranks", "last_dns_records",
}
_USEFUL_IP_KEYS = {
    "as_owner", "asn", "continent", "country", "network",
    "regional_internet_registry", "reputation", "tags", "total_votes",
    "whois", "last_https_certificate",
}
_USEFUL_FILE_KEYS = {
    "meaningful_name", "type_description", "type_tag", "size",
    "magic", "sha256", "sha1", "md5", "ssdeep", "tlsh",
    "creation_date", "first_submission_date", "last_submission_date",
    "last_modification_date", "reputation", "tags", "total_votes",
    "names", "popular_threat_classification", "sandbox_verdicts",
    "sigma_analysis_summary", "crowdsourced_yara_results",
}


def _extract_verdict_and_confidence(stats: dict[str, int] | None) -> tuple[str, float]:
    """根据 last_analysis_stats 得到 verdict 与 0~1 的 confidence。"""
    if not stats:
        return "unknown", 0.0
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected
    if total == 0:
        return "unknown", 0.0
    if malicious > 0:
        conf = min(0.5 + (malicious / total) * 0.5, 1.0)
        return ("malicious" if malicious >= 3 else "suspicious"), conf
    if suspicious > 0:
        return "suspicious", 0.3 + (suspicious / total) * 0.3
    if harmless > 0 and undetected <= harmless:
        return "benign", 0.3 + (harmless / total) * 0.4
    return "unknown", 0.0


def _filter_attrs(attrs: dict[str, Any], keys: set[str]) -> dict[str, Any]:
    """只保留有价值的属性键，减少数据量。"""
    return {k: v for k, v in attrs.items() if k in keys}


async def _vt_get(api_key: str, endpoint: str, timeout: float) -> dict[str, Any]:
    """通用 VT API GET 请求。"""
    url = VT_BASE + endpoint
    headers = {"accept": "application/json", "x-apikey": api_key}
    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(url, headers=headers, timeout=timeout)
            if r.status_code != 200:
                return {"_error": f"VT API error: {r.status_code}"}
            return r.json()
        except httpx.RequestError as e:
            return {"_error": f"VT request failed: {e}"}


def _build_result(
    data: dict[str, Any],
    useful_keys: set[str],
) -> dict[str, Any]:
    """从 VT 原始响应构建标准化结果。"""
    if "_error" in data:
        return {
            "verdict": "unknown",
            "confidence": 0.0,
            "summary": data["_error"],
            "stats": {},
            "tags": [],
            "details": {},
        }

    attrs = (data.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    verdict, confidence = _extract_verdict_and_confidence(stats)
    tags = attrs.get("tags") or []

    summary_parts = []
    for key in ("malicious", "suspicious", "harmless", "undetected"):
        if key in stats:
            summary_parts.append(f"{key}={stats[key]}")
    summary = ", ".join(summary_parts)

    details = _filter_attrs(attrs, useful_keys)

    return {
        "verdict": verdict,
        "confidence": confidence,
        "summary": summary,
        "stats": stats,
        "tags": tags,
        "details": details,
    }


# ---------------------------------------------------------------------------
# 公开查询函数
# ---------------------------------------------------------------------------

async def query_domain(api_key: str, domain: str, timeout: float = 30.0) -> dict[str, Any]:
    """查询域名，返回完整威胁情报。"""
    data = await _vt_get(api_key, f"domains/{domain}", timeout)
    return _build_result(data, _USEFUL_DOMAIN_KEYS)


async def query_ip(api_key: str, ip: str, timeout: float = 30.0) -> dict[str, Any]:
    """查询 IP，返回完整威胁情报。"""
    data = await _vt_get(api_key, f"ip_addresses/{ip}", timeout)
    return _build_result(data, _USEFUL_IP_KEYS)


async def query_file_hash(api_key: str, file_hash: str, timeout: float = 30.0) -> dict[str, Any]:
    """查询文件哈希（sha256/md5），返回完整威胁情报。"""
    data = await _vt_get(api_key, f"files/{file_hash}", timeout)
    return _build_result(data, _USEFUL_FILE_KEYS)


# ---------------------------------------------------------------------------
# 格式校验
# ---------------------------------------------------------------------------

def is_valid_domain(s: str) -> bool:
    s = (s or "").strip()
    if not s or len(s) > 253:
        return False
    return bool(re.match(r"^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$", s))


def is_valid_ip(s: str) -> bool:
    s = (s or "").strip()
    parts = s.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def is_valid_sha256(s: str) -> bool:
    return bool(s and re.match(r"^[a-fA-F0-9]{64}$", (s or "").strip()))


def is_valid_md5(s: str) -> bool:
    return bool(s and re.match(r"^[a-fA-F0-9]{32}$", (s or "").strip()))
