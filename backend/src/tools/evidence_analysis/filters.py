"""
智能过滤器：白名单过滤、基线对比、异常检测（`evidence_analysis` 子模块）。
"""
import hashlib
import re
from typing import Any

from src.tools.evidence_analysis.whitelists import (
    WINDOWS_SYSTEM_PROCESSES,
    WINDOWS_SYSTEM_SERVICES,
    TRUSTED_PUBLISHERS,
    get_whitelist,
)


def compute_item_hash(item: dict, fields: list[str]) -> str:
    """
    计算项的标识哈希（用于快速匹配和对比）。
    
    参数：
        item: 数据项
        fields: 用于计算哈希的字段列表
    
    返回：
        16字符的哈希值
    """
    key_values = [str(item.get(f, "")).lower() for f in fields]
    key_string = "|".join(key_values)
    return hashlib.sha256(key_string.encode()).hexdigest()[:16]


def filter_whitelist(
    items: list[dict],
    whitelist: list[dict] | str,
    filter_fields: list[str]
) -> dict[str, Any]:
    """
    白名单过滤。
    
    参数：
        items: 待过滤的数据项列表
        whitelist: 白名单列表或名称
            - list[dict]: 自定义白名单
            - str: 预定义白名单名称
                - "windows_system_processes"
                - "windows_system_services"
                - "trusted_publishers"
        filter_fields: 用于匹配的字段（如 ["process_name", "path"]）
    
    返回：
        {
            "filtered_items": [...],  # 未匹配白名单的项（可疑）
            "matched_items": [...],   # 匹配白名单的项
            "statistics": {
                "total": int,
                "filtered": int,
                "matched": int,
                "filter_rate": float
            }
        }
    """
    # 获取白名单
    if isinstance(whitelist, str):
        whitelist_items = get_whitelist(whitelist)
    else:
        whitelist_items = whitelist
    
    # 构建白名单哈希集合
    whitelist_hashes = {
        compute_item_hash(item, filter_fields)
        for item in whitelist_items
    }
    
    # 过滤
    filtered_items = []
    matched_items = []
    
    for item in items:
        item_hash = compute_item_hash(item, filter_fields)
        if item_hash in whitelist_hashes:
            matched_items.append(item)
        else:
            filtered_items.append(item)
    
    total = len(items)
    matched_count = len(matched_items)
    filtered_count = len(filtered_items)
    filter_rate = matched_count / total if total > 0 else 0.0
    
    return {
        "filtered_items": filtered_items,
        "matched_items": matched_items,
        "statistics": {
            "total": total,
            "filtered": filtered_count,
            "matched": matched_count,
            "filter_rate": filter_rate,
        }
    }


def baseline_compare(
    current_items: list[dict],
    baseline_items: list[dict],
    compare_fields: list[str],
    compare_mode: str = "diff"
) -> dict[str, Any]:
    """
    基线对比分析。
    
    参数：
        current_items: 当前状态数据
        baseline_items: 基线数据
        compare_fields: 用于比较的字段
        compare_mode: 对比模式
            - "diff": 完整差异（新增+删除+修改）
            - "added": 仅新增项
            - "removed": 仅删除项
            - "modified": 仅修改项
    
    返回：
        {
            "added": [...],      # 新增项
            "removed": [...],    # 删除项
            "modified": [...],   # 修改项（如果支持）
            "statistics": {
                "total_current": int,
                "total_baseline": int,
                "added_count": int,
                "removed_count": int,
                "modified_count": int
            }
        }
    """
    # 构建哈希映射
    baseline_map = {
        compute_item_hash(item, compare_fields): item
        for item in baseline_items
    }
    
    current_map = {
        compute_item_hash(item, compare_fields): item
        for item in current_items
    }
    
    # 计算差异
    added = []
    removed = []
    modified = []
    
    if compare_mode in ("diff", "added"):
        for item_hash, item in current_map.items():
            if item_hash not in baseline_map:
                added.append(item)
    
    if compare_mode in ("diff", "removed"):
        for item_hash, item in baseline_map.items():
            if item_hash not in current_map:
                removed.append(item)
    
    # 修改检测（基于全字段比较）
    if compare_mode in ("diff", "modified"):
        for item_hash in set(current_map.keys()) & set(baseline_map.keys()):
            current_item = current_map[item_hash]
            baseline_item = baseline_map[item_hash]
            
            # 比较所有字段
            if current_item != baseline_item:
                modified.append({
                    "current": current_item,
                    "baseline": baseline_item,
                    "changes": _compute_field_changes(current_item, baseline_item)
                })
    
    return {
        "added": added,
        "removed": removed,
        "modified": modified,
        "statistics": {
            "total_current": len(current_items),
            "total_baseline": len(baseline_items),
            "added_count": len(added),
            "removed_count": len(removed),
            "modified_count": len(modified),
        }
    }


def _compute_field_changes(current: dict, baseline: dict) -> dict[str, tuple]:
    """计算字段变化。"""
    changes = {}
    all_keys = set(current.keys()) | set(baseline.keys())
    
    for key in all_keys:
        current_val = current.get(key)
        baseline_val = baseline.get(key)
        if current_val != baseline_val:
            changes[key] = (baseline_val, current_val)
    
    return changes


def detect_anomalies(
    items: list[dict],
    detection_rules: list[dict]
) -> dict[str, Any]:
    """
    异常检测。
    
    参数：
        items: 数据项列表
        detection_rules: 检测规则列表
            规则格式：
            {
                "name": "rule_name",
                "type": "pattern" | "value_range" | "frequency",
                "field": "field_name",
                "pattern": r"regex",  # pattern类型
                "min": float,         # value_range类型
                "max": float,         # value_range类型
                "threshold": float,   # frequency类型
                "negate": bool,       # 是否取反
                "severity": "high" | "medium" | "low"
            }
    
    返回：
        {
            "anomalies": [
                {
                    "item": {...},
                    "rule": "rule_name",
                    "severity": "high",
                    "reason": "...",
                    "confidence": 0.9
                }
            ],
            "statistics": {
                "total_items": int,
                "anomaly_count": int,
                "high_severity": int,
                "medium_severity": int,
                "low_severity": int
            }
        }
    """
    anomalies = []
    
    for item in items:
        for rule in detection_rules:
            result = _apply_detection_rule(item, rule)
            if result:
                anomalies.append(result)
    
    # 统计
    severity_counts = {
        "high": sum(1 for a in anomalies if a["severity"] == "high"),
        "medium": sum(1 for a in anomalies if a["severity"] == "medium"),
        "low": sum(1 for a in anomalies if a["severity"] == "low"),
    }
    
    return {
        "anomalies": anomalies,
        "statistics": {
            "total_items": len(items),
            "anomaly_count": len(anomalies),
            "high_severity": severity_counts["high"],
            "medium_severity": severity_counts["medium"],
            "low_severity": severity_counts["low"],
        }
    }


def _apply_detection_rule(item: dict, rule: dict) -> dict | None:
    """应用单个检测规则。"""
    rule_type = rule.get("type", "pattern")
    field = rule.get("field")
    negate = rule.get("negate", False)
    severity = rule.get("severity", "medium")
    
    if field not in item:
        return None
    
    value = item[field]
    matched = False
    reason = ""
    
    if rule_type == "pattern":
        # 模式匹配
        pattern = rule.get("pattern", "")
        if pattern:
            matched = bool(re.search(pattern, str(value), re.IGNORECASE))
            reason = f"匹配模式: {pattern}"
    
    elif rule_type == "value_range":
        # 数值范围检测
        try:
            num_value = float(value)
            min_val = rule.get("min", float('-inf'))
            max_val = rule.get("max", float('inf'))
            matched = not (min_val <= num_value <= max_val)
            reason = f"数值超出范围 [{min_val}, {max_val}]"
        except (ValueError, TypeError):
            pass
    
    elif rule_type == "frequency":
        # 频率异常（需要全局统计，此处简化）
        threshold = rule.get("threshold", 0.01)
        # 简化实现：假设 value 包含频率信息
        if isinstance(value, (int, float)):
            matched = value > threshold
            reason = f"频率超过阈值 {threshold}"
    
    # 应用取反逻辑
    if negate:
        matched = not matched
        reason = f"NOT ({reason})"
    
    if matched:
        return {
            "item": item,
            "rule": rule.get("name", "unknown"),
            "severity": severity,
            "reason": reason,
            "confidence": 0.8,  # 简化实现，固定置信度
        }
    
    return None
