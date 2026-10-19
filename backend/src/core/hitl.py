"""
人机协作审批（HITL）存储。

需要审批的工具调用会先存入 pending，用户批准后存入 approved，
工具执行时检查 approved 并清除。
"""
import hashlib
import logging
import time
from typing import Any

logger = logging.getLogger(__name__)

# session_id -> {tool, args, args_hash, timestamp}
_pending: dict[str, dict[str, Any]] = {}
# session_id -> {tool, args_hash} 批准后存入，执行后清除
_approved: dict[str, dict[str, Any]] = {}

HITL_REQUIRED_TOOLS = frozenset({"run_dynamic_analysis"})
HITL_ENABLED = True  # 可通过配置关闭
PENDING_EXPIRE_SECONDS = 600  # 10 分钟


def _args_hash(args: dict[str, Any]) -> str:
    """生成参数哈希，用于匹配审批。"""
    import json
    try:
        s = json.dumps(args, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(s.encode()).hexdigest()[:16]
    except Exception:
        return ""


def check_approval(session_id: str, tool_name: str, args: dict[str, Any]) -> bool:
    """检查是否有该工具调用的审批。"""
    if not HITL_ENABLED or tool_name not in HITL_REQUIRED_TOOLS:
        return True
    key = f"{session_id}:{tool_name}"
    approved = _approved.get(key)
    if not approved:
        return False
    args_hash = _args_hash(args)
    if approved.get("args_hash") != args_hash:
        return False
    return True


def consume_approval(session_id: str, tool_name: str, args: dict[str, Any]) -> bool:
    """检查并消耗审批（执行后调用）。"""
    key = f"{session_id}:{tool_name}"
    if not check_approval(session_id, tool_name, args):
        return False
    _approved.pop(key, None)
    return True


def store_pending(session_id: str, tool_name: str, args: dict[str, Any]) -> str:
    """存储待审批的工具调用，返回 approval_id。"""
    args_hash = _args_hash(args)
    approval_id = f"{session_id}:{tool_name}:{args_hash}"
    _pending[approval_id] = {
        "session_id": session_id,
        "tool": tool_name,
        "args": args,
        "args_hash": args_hash,
        "timestamp": time.time(),
    }
    return approval_id


def approve_tool(session_id: str, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
    """
    用户批准工具调用。
    从 pending 移至 approved。
    """
    args_hash = _args_hash(args)
    approval_id = f"{session_id}:{tool_name}:{args_hash}"
    pending = _pending.pop(approval_id, None)
    if not pending:
        return {"ok": False, "error": "未找到待审批项或已过期"}
    _approved[f"{session_id}:{tool_name}"] = {"args_hash": args_hash, "args": args}
    return {"ok": True, "approval_id": approval_id}


def get_pending(session_id: str) -> list[dict[str, Any]]:
    """获取会话下所有待审批项。"""
    now = time.time()
    result = []
    expired = []
    for aid, data in _pending.items():
        if not aid.startswith(session_id + ":"):
            continue
        if now - data.get("timestamp", 0) > PENDING_EXPIRE_SECONDS:
            expired.append(aid)
            continue
        result.append({
            "approval_id": aid,
            "tool": data["tool"],
            "args": data["args"],
        })
    for aid in expired:
        _pending.pop(aid, None)
    return result
