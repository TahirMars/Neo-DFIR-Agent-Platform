"""
深信服威胁情报 API 异步客户端（参考 ref/mcp-server/mcp-ti/tisangfor.py）。
查询域名/IP/哈希的声誉、标签、描述、关联文件、地理信息、动态分析及网络行为。
仅在配置 SANGFOR_COOKIE 与 SANGFOR_CSRF_TOKEN 时启用。
"""
from __future__ import annotations

import base64
import logging
import ssl
from typing import Any

import httpx

logger = logging.getLogger(__name__)

SANGFOR_BASE = "https://ti.sangfor.com.cn/api/v1/"


def _b64_ioc(ioc: str) -> str:
    return base64.b64encode(ioc.encode("utf-8")).decode("ascii")


_REPUTATION_MAP = {"1": "benign", "0": "malicious", "3": "suspicious", "2": "unknown"}


def _make_ssl_context() -> ssl.SSLContext:
    """构建兼容深信服 TI 服务器的 SSL 上下文。
    服务端仅支持 AES256-SHA256 等非 PFS 套件，需降低 SECLEVEL 至 1。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
    return ctx


async def _request(url: str, cookie: str, csrf_token: str, timeout: float = 30.0) -> dict[str, Any]:
    """发起深信服 TI API 请求，返回 JSON 或 {"error": ...}。"""
    ssl_ctx = _make_ssl_context()
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Cookie": cookie,
        "X-CSRFToken": csrf_token,
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "Mozilla/5.0 (compatible; Neo-TI/1.0)",
    }
    async with httpx.AsyncClient(verify=ssl_ctx) as client:
        try:
            r = await client.get(url, headers=headers, timeout=timeout)
            if r.status_code != 200:
                return {"error": f"HTTP {r.status_code}"}
            return r.json()
        except httpx.RequestError as e:
            return {"error": str(e)}


def _parse_labels_domain(data: dict) -> list[str]:
    """从域名响应中提取标签列表。"""
    labels: list[str] = []
    for lbl in data.get("labels") or []:
        if isinstance(lbl, str) and lbl:
            labels.append(lbl)
    return labels


def _parse_labels_ip(data: dict) -> list[str]:
    """从 IP 响应中提取标签列表（label_class 结构）。"""
    labels: list[str] = []
    for lc in data.get("label_class") or []:
        cat = lc.get("category")
        if cat:
            labels.append(cat)
        for sc in lc.get("sub_class") or []:
            if sc:
                labels.append(sc)
    return labels


# ---------------------------------------------------------------------------
# 域名查询
# ---------------------------------------------------------------------------

async def query_domain_sangfor(
    cookie: str, csrf_token: str, domain: str, timeout: float = 30.0,
) -> dict[str, Any]:
    """查询域名的完整威胁情报（声誉 + 关联通信文件）。"""
    reputation = await _query_domain_reputation(cookie, csrf_token, domain, timeout)
    related_files = await _query_domain_related_com_file(cookie, csrf_token, domain, timeout)
    reputation["related_files"] = related_files
    return reputation


async def _query_domain_reputation(
    cookie: str, csrf_token: str, domain: str, timeout: float,
) -> dict[str, Any]:
    url = SANGFOR_BASE + f"domain/reputation?query={_b64_ioc(domain)}"
    data = await _request(url, cookie, csrf_token, timeout)
    if "error" in data:
        return _error_result(data["error"])
    if data.get("success") != 1:
        return _error_result("sangfor no data")

    inner = data.get("data") or {}
    rep = str(inner.get("reputation", "2"))
    verdict = _REPUTATION_MAP.get(rep, "unknown")
    labels = _parse_labels_domain(inner)

    result: dict[str, Any] = {
        "verdict": verdict,
        "confidence": 0.85 if verdict in ("malicious", "benign") else 0.4,
        "summary": verdict,
        "labels": labels,
        "description": inner.get("description", ""),
        "first_found_time": inner.get("first_found_time", ""),
        "update_time": inner.get("update_time", ""),
        "sangfor_response": inner.get("response", ""),
    }
    return result


async def _query_domain_related_com_file(
    cookie: str, csrf_token: str, domain: str, timeout: float,
) -> list[dict[str, str]]:
    url = SANGFOR_BASE + f"domain/related_com_file?query={_b64_ioc(domain)}"
    data = await _request(url, cookie, csrf_token, timeout)
    if "error" in data or data.get("success") != 1 or not data.get("data"):
        return []
    files: list[dict[str, str]] = []
    for item in data["data"]:
        files.append({
            "name": item.get("name", ""),
            "file_md5": item.get("file_md5", ""),
            "virus_name": item.get("virus_name", ""),
        })
    return files


# ---------------------------------------------------------------------------
# IP 查询
# ---------------------------------------------------------------------------

async def query_ip_sangfor(
    cookie: str, csrf_token: str, ip: str, timeout: float = 30.0,
) -> dict[str, Any]:
    """查询 IP 的完整威胁情报（声誉 + 地理位置 + 关联通信文件）。"""
    reputation = await _query_ip_reputation(cookie, csrf_token, ip, timeout)
    geo = await _query_ip_geo(cookie, csrf_token, ip, timeout)
    related_files = await _query_ip_related_com_file(cookie, csrf_token, ip, timeout)
    reputation["geo"] = geo
    reputation["related_files"] = related_files
    return reputation


async def _query_ip_reputation(
    cookie: str, csrf_token: str, ip: str, timeout: float,
) -> dict[str, Any]:
    url = SANGFOR_BASE + f"ip/reputation?query={_b64_ioc(ip)}"
    data = await _request(url, cookie, csrf_token, timeout)
    if "error" in data:
        return _error_result(data["error"])
    if data.get("success") != 1:
        return _error_result("sangfor no data")

    inner = data.get("data") or {}
    rep = str(inner.get("reputation", "2"))
    verdict = _REPUTATION_MAP.get(rep, "unknown")
    labels = _parse_labels_ip(inner)

    return {
        "verdict": verdict,
        "confidence": 0.85 if verdict in ("malicious", "benign") else 0.4,
        "summary": verdict,
        "labels": labels,
        "description": inner.get("description", ""),
        "first_found_time": inner.get("first_found_time", ""),
        "update_time": inner.get("update_time", ""),
        "sangfor_response": inner.get("response", ""),
    }


async def _query_ip_geo(
    cookie: str, csrf_token: str, ip: str, timeout: float,
) -> dict[str, Any]:
    url = SANGFOR_BASE + f"ip/geo?query={_b64_ioc(ip)}"
    data = await _request(url, cookie, csrf_token, timeout)
    if "error" in data or data.get("success") != 1 or not data.get("data"):
        return {}
    return data["data"] if isinstance(data["data"], dict) else {}


async def _query_ip_related_com_file(
    cookie: str, csrf_token: str, ip: str, timeout: float,
) -> list[dict[str, str]]:
    url = SANGFOR_BASE + f"ip/related_com_file?query={_b64_ioc(ip)}"
    data = await _request(url, cookie, csrf_token, timeout)
    if "error" in data or data.get("success") != 1 or not data.get("data"):
        return []
    files: list[dict[str, str]] = []
    for item in data["data"]:
        files.append({
            "name": item.get("name", ""),
            "file_md5": item.get("file_md5", ""),
            "virus_name": item.get("virus_name", ""),
        })
    return files


# ---------------------------------------------------------------------------
# 哈希查询
# ---------------------------------------------------------------------------

async def query_hash_sangfor(
    cookie: str, csrf_token: str, file_hash: str, timeout: float = 30.0,
) -> dict[str, Any]:
    """查询文件哈希的完整威胁情报（声誉 + 文件信息 + 动态分析 + 网络行为 + 关联文件）。"""
    reputation = await _query_hash_reputation(cookie, csrf_token, file_hash, timeout)
    file_info = await _query_hash_info(cookie, csrf_token, file_hash, timeout)
    dynamic_analysis = await _query_hash_dynamic_analysis(cookie, csrf_token, file_hash, timeout)
    network_behavior = await _query_hash_network_behavior(cookie, csrf_token, file_hash, timeout)
    related_files = await _query_hash_related_file(cookie, csrf_token, file_hash, timeout)
    reputation["file_info"] = file_info
    reputation["dynamic_analysis"] = dynamic_analysis
    reputation["network_behavior"] = network_behavior
    reputation["related_files"] = related_files
    return reputation


async def _query_hash_reputation(
    cookie: str, csrf_token: str, file_hash: str, timeout: float,
) -> dict[str, Any]:
    url = SANGFOR_BASE + f"file/reputation?query={file_hash}"
    data = await _request(url, cookie, csrf_token, timeout)
    if "error" in data:
        return _error_result(data["error"])
    if data.get("success") != 1:
        return _error_result("sangfor no data")

    inner = data.get("data") or {}
    rep = str(inner.get("reputation", "2"))
    verdict = _REPUTATION_MAP.get(rep, "unknown")

    return {
        "verdict": verdict,
        "confidence": 0.85 if verdict in ("malicious", "benign") else 0.4,
        "summary": verdict,
        "labels": [],
        "description": "",
        "first_found_time": "",
        "update_time": "",
    }


async def _query_hash_info(
    cookie: str, csrf_token: str, file_hash: str, timeout: float,
) -> dict[str, Any]:
    url = SANGFOR_BASE + f"file/info?query={file_hash}"
    data = await _request(url, cookie, csrf_token, timeout)
    if "error" in data or data.get("success") != 1 or not data.get("data"):
        return {}
    return data["data"] if isinstance(data["data"], dict) else {}


async def _query_hash_dynamic_analysis(
    cookie: str, csrf_token: str, file_hash: str, timeout: float,
) -> dict[str, Any]:
    """沙箱动态威胁分析（analysis_list + threat_label_list）。"""
    url = SANGFOR_BASE + f"file/dym_threat_analysis?query={file_hash}&sandbox_type=c&system_type=win10_64"
    data = await _request(url, cookie, csrf_token, timeout)
    if "error" in data or data.get("success") != 1 or not data.get("data"):
        return {}
    inner = data["data"]
    return {
        "analysis_list": inner.get("analysis_list", []),
        "threat_label_list": inner.get("threat_label_list", []),
    }


async def _query_hash_network_behavior(
    cookie: str, csrf_token: str, file_hash: str, timeout: float,
) -> dict[str, Any]:
    """沙箱网络行为分析（dns_parse_list + network_list）。"""
    url = SANGFOR_BASE + f"file/network_behavior?query={file_hash}&sandbox_type=c&system_type=win10_64"
    data = await _request(url, cookie, csrf_token, timeout)
    if "error" in data or data.get("success") != 1 or not data.get("data"):
        return {}
    inner = data["data"]
    return {
        "dns_parse_list": inner.get("dns_parse_list", []),
        "network_list": inner.get("network_list", []),
    }


async def _query_hash_related_file(
    cookie: str, csrf_token: str, file_hash: str, timeout: float,
) -> list[dict[str, Any]]:
    url = SANGFOR_BASE + f"file/related_file?query={file_hash}"
    data = await _request(url, cookie, csrf_token, timeout)
    if "error" in data or data.get("success") != 1 or not data.get("data"):
        return []
    if isinstance(data["data"], list):
        return data["data"]
    return []


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------

def _error_result(msg: str) -> dict[str, Any]:
    return {
        "verdict": "unknown",
        "confidence": 0.0,
        "summary": msg,
        "labels": [],
        "description": "",
        "first_found_time": "",
        "update_time": "",
    }
