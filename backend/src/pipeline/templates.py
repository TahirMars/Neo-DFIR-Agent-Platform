"""
流水线模板定义与加载。
"""
from typing import Any

_PIPELINES: list[dict[str, Any]] = [
    {
        "id": "single_host_quick",
        "name": "单主机快速分析",
        "description": "对单台主机的取证数据包进行快速 IOC 扫描和威胁识别，适用于应急响应初筛",
        "steps": ["evidence_classify", "forensic_analysis", "sample_analysis", "report_generation"],
    },
    {
        "id": "full_investigation",
        "name": "完整溯源调查",
        "description": "完整的 DFIR 溯源调查流程：证据分类 → 日志分析 → 样本分析 → 威胁情报关联 → 攻击链重建 → 报告生成",
        "steps": ["evidence_classify", "forensic_analysis", "sample_analysis", "ti_enrichment", "attack_chain", "report_generation"],
    },
    {
        "id": "ioc_scan_only",
        "name": "仅 IOC 扫描",
        "description": "仅提取和分析证据中的 IOC（不做深度样本分析），适用于快速情报收集",
        "steps": ["evidence_classify", "forensic_analysis", "report_generation"],
    },
    {
        "id": "sample_analysis_only",
        "name": "仅样本分析",
        "description": "仅对二进制样本进行静态分析，适用于已知恶意样本的快速研判",
        "steps": ["evidence_classify", "sample_analysis", "report_generation"],
    },
]


def list_pipelines() -> list[dict[str, Any]]:
    """返回所有可用流水线模板。"""
    return _PIPELINES


def get_pipeline(pipeline_id: str) -> dict[str, Any] | None:
    """按 ID 获取流水线模板。"""
    for p in _PIPELINES:
        if p["id"] == pipeline_id:
            return p
    return None
