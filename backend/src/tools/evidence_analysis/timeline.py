"""
时间线分析：统一多源日志时间线、事件查询、汇总统计（`evidence_analysis` 子模块）。
"""
import re
from datetime import datetime, timezone
from typing import Any


def normalize_timestamp(
    value: str | int | float,
    format: str = "auto"
) -> tuple[datetime, float]:
    """
    标准化时间戳为 UTC datetime 和 Unix 时间戳。
    
    支持格式：
        - iso8601: 2026-01-30T08:00:00Z
        - unix: 1738224000 (秒) 或 1738224000000 (毫秒)
        - windows_filetime: 133503360000000000
        - rfc2822: Wed, 30 Jan 2026 08:00:00 +0000
        - custom: strftime 格式字符串
    
    返回：
        (datetime对象, Unix时间戳秒)
    """
    if format == "auto":
        format = _detect_timestamp_format(value)
    
    dt = None
    
    if format == "iso8601":
        # ISO 8601: 2026-01-30T08:00:00Z
        if isinstance(value, str):
            # 处理各种ISO格式变体
            value = value.replace(' ', 'T')
            if not value.endswith('Z') and '+' not in value and '-' not in value[-6:]:
                value += 'Z'
            dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    
    elif format == "unix":
        # Unix 时间戳
        num = float(value)
        # 区分秒和毫秒
        if num > 1e10:  # 毫秒
            num = num / 1000
        dt = datetime.fromtimestamp(num, tz=timezone.utc)
    
    elif format == "windows_filetime":
        # Windows FILETIME (100纳秒单位，从1601-01-01起)
        filetime = int(value)
        unix_epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
        windows_epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        delta = (unix_epoch - windows_epoch).total_seconds()
        timestamp = (filetime / 10_000_000) - delta
        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    
    elif format == "rfc2822":
        # RFC 2822: Wed, 30 Jan 2026 08:00:00 +0000
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(str(value))
    
    else:
        # 自定义格式（strftime）
        if isinstance(value, str):
            dt = datetime.strptime(value, format)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
    
    if dt is None:
        raise ValueError(f"无法解析时间戳: {value}, 格式: {format}")
    
    # 确保UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    
    unix_timestamp = dt.timestamp()
    
    return dt, unix_timestamp


def _detect_timestamp_format(value: str | int | float) -> str:
    """自动检测时间戳格式。"""
    if isinstance(value, (int, float)):
        num = float(value)
        if num > 1e17:  # Windows FILETIME
            return "windows_filetime"
        return "unix"
    
    if isinstance(value, str):
        # ISO 8601
        if re.match(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', value):
            return "iso8601"
        
        # RFC 2822
        if re.match(r'[A-Z][a-z]{2}, \d{1,2} [A-Z][a-z]{2} \d{4}', value):
            return "rfc2822"
        
        # Unix (纯数字字符串)
        if value.isdigit():
            return "unix"
    
    return "iso8601"  # 默认


def build_timeline(
    data_sources: list[dict],
    time_field: str = "timestamp",
    time_format: str = "auto"
) -> dict[str, Any]:
    """
    构建统一时间线。
    
    参数：
        data_sources: 数据源列表
            [
                {
                    "source": "source_label",
                    "data": [{...}, ...],  # 数据列表
                    "time_field": "TimeCreated",  # 时间字段（可选，默认用全局）
                    "time_format": "iso8601",     # 时间格式（可选，默认用全局）
                    "event_type_field": "EventID",  # 事件类型字段（可选）
                },
                ...
            ]
        time_field: 默认时间字段名
        time_format: 默认时间格式
    
    返回：
        {
            "timeline": [
                {
                    "timestamp": "2026-01-30T08:00:00Z",
                    "timestamp_unix": 1738224000.0,
                    "source": "Windows Event Log",
                    "event_type": "4624",
                    "event_data": {...},
                    "original_record": {...}
                },
                ...
            ],
            "statistics": {...}
        }
    """
    timeline_events = []
    source_stats = {}
    
    for ds in data_sources:
        source_label = ds.get("source", "Unknown")
        data = ds.get("data", [])
        ds_time_field = ds.get("time_field", time_field)
        ds_time_format = ds.get("time_format", time_format)
        event_type_field = ds.get("event_type_field")
        
        source_count = 0
        
        for record in data:
            if ds_time_field not in record:
                continue
            
            try:
                dt, unix_ts = normalize_timestamp(
                    record[ds_time_field],
                    ds_time_format
                )
                
                event = {
                    "timestamp": dt.isoformat(),
                    "timestamp_unix": unix_ts,
                    "source": source_label,
                    "event_type": record.get(event_type_field) if event_type_field else None,
                    "event_data": {k: v for k, v in record.items() if k != ds_time_field},
                    "original_record": record,
                }
                
                timeline_events.append(event)
                source_count += 1
            except Exception:
                # 忽略无法解析的时间戳
                continue
        
        source_stats[source_label] = source_count
    
    # 按时间戳排序
    timeline_events.sort(key=lambda e: e["timestamp_unix"])
    
    # 计算时间范围
    if timeline_events:
        start_ts = timeline_events[0]["timestamp_unix"]
        end_ts = timeline_events[-1]["timestamp_unix"]
        duration = end_ts - start_ts
        
        time_range = {
            "start": timeline_events[0]["timestamp"],
            "end": timeline_events[-1]["timestamp"],
            "duration_seconds": duration,
        }
    else:
        time_range = None
    
    return {
        "timeline": timeline_events,
        "statistics": {
            "total_events": len(timeline_events),
            "time_range": time_range,
            "sources": source_stats,
        }
    }


def query_timeline(
    timeline_events: list[dict],
    filters: dict | None = None
) -> dict[str, Any]:
    """
    时间线查询与筛选。
    
    参数：
        timeline_events: 时间线事件列表（来自 build_timeline）
        filters: 过滤条件
            {
                "time_range": {
                    "start": "2026-01-30T08:00:00Z",
                    "end": "2026-01-30T09:00:00Z"
                },
                "sources": ["Windows Event Log"],
                "event_types": ["4624", "4625"],
                "keywords": ["administrator", "failed"],
                "limit": 1000,
                "sort": "asc"  # asc | desc
            }
    
    返回：
        {
            "events": [...],
            "total_matched": int,
            "truncated": bool
        }
    """
    filters = filters or {}
    matched_events = timeline_events.copy()
    
    # 时间范围过滤
    if "time_range" in filters:
        time_range = filters["time_range"]
        start_str = time_range.get("start")
        end_str = time_range.get("end")
        
        if start_str:
            start_dt, start_unix = normalize_timestamp(start_str)
            matched_events = [e for e in matched_events if e["timestamp_unix"] >= start_unix]
        
        if end_str:
            end_dt, end_unix = normalize_timestamp(end_str)
            matched_events = [e for e in matched_events if e["timestamp_unix"] <= end_unix]
    
    # 数据源过滤
    if "sources" in filters:
        sources = filters["sources"]
        matched_events = [e for e in matched_events if e["source"] in sources]
    
    # 事件类型过滤
    if "event_types" in filters:
        event_types = [str(t) for t in filters["event_types"]]
        matched_events = [e for e in matched_events 
                         if e["event_type"] and str(e["event_type"]) in event_types]
    
    # 关键词过滤
    if "keywords" in filters:
        keywords = [kw.lower() for kw in filters["keywords"]]
        
        def match_keywords(event: dict) -> bool:
            # 在整个事件记录中搜索关键词
            event_str = str(event).lower()
            return any(kw in event_str for kw in keywords)
        
        matched_events = [e for e in matched_events if match_keywords(e)]
    
    # 排序
    sort_order = filters.get("sort", "asc")
    if sort_order == "desc":
        matched_events.reverse()
    
    # 限制数量
    limit = filters.get("limit", 10000)
    truncated = len(matched_events) > limit
    matched_events = matched_events[:limit]
    
    return {
        "events": matched_events,
        "total_matched": len(matched_events),
        "truncated": truncated,
    }


def timeline_summary(
    timeline_events: list[dict],
    bucket_size: str = "1hour"
) -> dict[str, Any]:
    """
    时间线汇总统计（用于可视化）。
    
    参数：
        bucket_size: 时间桶大小
            - "1min": 1分钟
            - "5min": 5分钟
            - "15min": 15分钟
            - "1hour": 1小时
            - "1day": 1天
    
    返回：
        {
            "buckets": [
                {
                    "timestamp": "2026-01-30T08:00:00Z",
                    "count": 150,
                    "sources": {
                        "Windows Event Log": 80,
                        "Web Access Log": 40
                    }
                },
                ...
            ],
            "hotspots": [  # 事件密集时段
                {
                    "timestamp": "2026-01-30T08:30:00Z",
                    "count": 500,
                    "score": 0.95
                }
            ]
        }
    """
    if not timeline_events:
        return {"buckets": [], "hotspots": []}
    
    # 确定桶大小（秒）
    bucket_sizes = {
        "1min": 60,
        "5min": 300,
        "15min": 900,
        "1hour": 3600,
        "1day": 86400,
    }
    bucket_seconds = bucket_sizes.get(bucket_size, 3600)
    
    # 按桶分组
    buckets_map: dict[int, dict] = {}
    
    for event in timeline_events:
        unix_ts = event["timestamp_unix"]
        bucket_key = int(unix_ts // bucket_seconds) * bucket_seconds
        
        if bucket_key not in buckets_map:
            buckets_map[bucket_key] = {
                "timestamp": datetime.fromtimestamp(bucket_key, tz=timezone.utc).isoformat(),
                "timestamp_unix": bucket_key,
                "count": 0,
                "sources": {},
            }
        
        buckets_map[bucket_key]["count"] += 1
        source = event["source"]
        buckets_map[bucket_key]["sources"][source] = \
            buckets_map[bucket_key]["sources"].get(source, 0) + 1
    
    # 排序桶
    buckets = sorted(buckets_map.values(), key=lambda b: b["timestamp_unix"])
    
    # 检测热点（事件密集时段）
    if buckets:
        counts = [b["count"] for b in buckets]
        avg_count = sum(counts) / len(counts)
        std_dev = (sum((c - avg_count) ** 2 for c in counts) / len(counts)) ** 0.5
        threshold = avg_count + 2 * std_dev  # 超过平均值+2倍标准差
        
        hotspots = [
            {
                "timestamp": b["timestamp"],
                "count": b["count"],
                "score": min(1.0, (b["count"] - avg_count) / (3 * std_dev if std_dev > 0 else 1))
            }
            for b in buckets
            if b["count"] > threshold
        ]
    else:
        hotspots = []
    
    return {
        "buckets": buckets,
        "hotspots": hotspots,
    }
