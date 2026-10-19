"""
证据分析包：在 `evidence.tools`（存储/清单/路径级读写）之上提供
结构化解析（parsers）、过滤与基线（filters）、时间线（timeline）、
白名单数据（whitelists），以及 `api` 中与 envelope、artifact、证据路径的衔接。
"""

from src.tools.evidence_analysis.api import (
    build_evidence_timeline,
    compare_evidence_baseline,
    detect_evidence_anomalies,
    filter_evidence_whitelist,
    parse_evidence_structured,
    query_evidence_timeline,
    summarize_evidence_timeline,
)
from src.tools.evidence_analysis.parsers import (
    MAX_FILE_SIZE,
    MAX_ROWS,
    detect_format,
    parse_structured_data,
    parse_structured_data_bytes,
)

__all__ = [
    "MAX_FILE_SIZE",
    "MAX_ROWS",
    "detect_format",
    "parse_structured_data",
    "parse_structured_data_bytes",
    "parse_evidence_structured",
    "filter_evidence_whitelist",
    "compare_evidence_baseline",
    "detect_evidence_anomalies",
    "build_evidence_timeline",
    "query_evidence_timeline",
    "summarize_evidence_timeline",
]
