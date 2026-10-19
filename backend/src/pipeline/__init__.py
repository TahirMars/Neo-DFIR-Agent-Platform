"""
流水线模块：模板定义与执行引擎。

- templates: 流水线模板（单主机快速分析、完整溯源等）
- engine: 根据模板驱动多智能体图执行
"""
from src.pipeline.engine import run_pipeline
from src.pipeline.templates import get_pipeline, list_pipelines

__all__ = ["run_pipeline", "get_pipeline", "list_pipelines"]
