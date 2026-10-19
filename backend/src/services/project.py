"""
项目/空间与配额服务：租户、配额校验。
供编排器与 API 使用；未配置 Redis 时使用内存或默认配置。
"""
from typing import Any

# 默认每会话/每项目上限（可后续从配置或 Redis 读取）
DEFAULT_QUOTA = {
    "ti_iocs_per_session": 500,
    "dynamic_samples_per_session": 10,
    "hypothesis_per_session": 50,
}

# 内存中每会话已使用量（可选；后续可换 Redis）
_session_usage: dict[str, dict[str, int]] = {}


def get_project_quota(project_id: str) -> dict[str, Any]:
    """
    返回项目配额配置（如每会话 TI 条数、动态分析样本数、协同分析假设数）。
    当前返回默认值；后续可从 Redis 或配置中心读取。
    """
    return dict(DEFAULT_QUOTA)


def check_quota(
    project_id: str,
    session_id: str,
    resource_type: str,
    delta: int = 1,
) -> tuple[bool, str]:
    """
    检查并扣减配额。resource_type 如 ti_iocs、dynamic_samples、hypothesis。
    返回 (是否允许, 错误信息)；允许时内部扣减已用量（内存）。
    """
    quota = get_project_quota(project_id)
    key_map = {
        "ti_iocs": "ti_iocs_per_session",
        "dynamic_samples": "dynamic_samples_per_session",
        "hypothesis": "hypothesis_per_session",
    }
    key = key_map.get(resource_type) or resource_type
    limit = quota.get(key)
    if limit is None:
        return True, ""
    usage = _session_usage.setdefault(session_id, {})
    current = usage.get(resource_type, 0)
    if current + delta > limit:
        return False, f"会话 {resource_type} 已达上限 {limit}"
    usage[resource_type] = current + delta
    return True, ""


def get_session_usage(session_id: str) -> dict[str, int]:
    """返回某会话当前已用配额（测试/调试用）。"""
    return dict(_session_usage.get(session_id, {}))
