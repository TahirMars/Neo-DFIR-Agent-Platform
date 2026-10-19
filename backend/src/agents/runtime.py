"""
单智能体运行时：根据 agent_type 加载配置并调用 LLM。
用于非 LangGraph 模式下的单 Agent 交互（回退路径）。

v2: 使用统一的 ChatOpenAI 层替代 AsyncOpenAI 直连。
"""
import logging
import time
from collections.abc import Callable
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from src.agents.common import AgentContext
from src.agents.llm import extract_chunk_text, get_chat_model, normalize_message_content
from src.agents.registry import get_agent_config
from src.core.audit import record_mcp_call
from src.core.config import get_settings

logger = logging.getLogger(__name__)


async def run_agent(
    agent_type: str,
    context: AgentContext,
    request_id: str | None = None,
    enable_thinking: bool = False,
    on_token: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """
    执行单个智能体（非 LangGraph 回退路径）：
    1. 加载 agent_type 对应配置
    2. 构建消息
    3. 调用 LLM
    4. 记录审计日志
    """
    config = get_agent_config(agent_type)
    system_prompt = config.get("system_prompt", "")
    max_tokens = config.get("max_tokens", 8192)

    messages = []
    if system_prompt:
        messages.append(SystemMessage(content=system_prompt))
    if context.context_summary:
        messages.append(SystemMessage(content=context.context_summary))
    mem_max = get_settings().session_memory_single_msg_max_chars
    for m in context.session_memory or []:
        role = m.get("role", "user")
        content = m.get("content", "")
        if role in ("user", "assistant") and content.strip():
            if role == "user":
                messages.append(HumanMessage(content=content[:mem_max]))
            else:
                from langchain_core.messages import AIMessage
                messages.append(AIMessage(content=content[:mem_max]))
    if context.user_message.strip():
        messages.append(HumanMessage(content=context.user_message))

    model = get_chat_model(max_tokens=max_tokens)

    t0 = time.time()
    try:
        if on_token:
            reply_parts: list[str] = []
            async for chunk in model.astream(messages):
                text = extract_chunk_text(chunk)
                if text:
                    reply_parts.append(text)
                    on_token(text)
            reply = "".join(reply_parts)
        else:
            result = await model.ainvoke(messages)
            reply = normalize_message_content(getattr(result, "content", None))
        duration_ms = int((time.time() - t0) * 1000)
        record_mcp_call(
            tool_name=f"agent.{agent_type}",
            case_id=context.case_id,
            session_id=context.session_id,
            request_id=request_id,
            arguments_summary={"user_message_len": len(context.user_message), "memory_len": len(context.session_memory)},
            result_ok=True,
            result_summary={"reply_len": len(reply)},
            duration_ms=duration_ms,
        )
        return {"explanation": reply, "agent_type": agent_type}
    except Exception as e:
        duration_ms = int((time.time() - t0) * 1000)
        logger.error("Agent %s 执行失败: %s", agent_type, e)
        record_mcp_call(
            tool_name=f"agent.{agent_type}",
            case_id=context.case_id,
            session_id=context.session_id,
            request_id=request_id,
            arguments_summary={"user_message_len": len(context.user_message)},
            result_ok=False,
            result_summary=None,
            duration_ms=duration_ms,
            errors=[str(e)],
        )
        return {"explanation": f"智能体执行异常：{e}", "agent_type": agent_type, "error": str(e)}
