"""
SSE / 实时流统一事件信封（P0 方案）。

每条 data: 行为 JSON：v, run_id, seq, ts, kind, payload。
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any


class StreamKind:
    """与前端 NeoStreamKind 对齐。"""

    RUN_STARTED = "run.started"
    RUN_COMPLETED = "run.completed"
    RUN_FAILED = "run.failed"
    GRAPH_STEP = "graph.step"
    AGENT_START = "agent.start"
    AGENT_END = "agent.end"
    LLM_DELTA = "llm.delta"
    TOOL_CALLS = "tool.calls"
    HITL_REQUIRED = "hitl.required"
    AGENT_ERROR = "agent.error"


def new_run_id() -> str:
    return str(uuid.uuid4())


def format_sse_data(
    run_id: str,
    seq: int,
    kind: str,
    payload: dict[str, Any] | None = None,
    *,
    version: int = 1,
) -> str:
    body: dict[str, Any] = {
        "v": version,
        "run_id": run_id,
        "seq": seq,
        "ts": datetime.now(timezone.utc).isoformat(),
        "kind": kind,
        "payload": payload if payload is not None else {},
    }
    return f"data: {json.dumps(body, ensure_ascii=False)}\n\n"
