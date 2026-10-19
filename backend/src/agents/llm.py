"""
LLM 调用封装：通过 OpenAI 兼容接口调用大模型（如通义千问）。

v2: 统一使用 LangChain ChatOpenAI 层，供 create_react_agent 和 Supervisor 共用。
    移除原 AsyncOpenAI 直连层（chat_completion / build_messages 等）。

P2: ReAct 图在需要逐 token 展示时通过 astream_events(v2) + on_chat_model_stream 转发可见文本；
    失败时回退 ainvoke，由调用方决定是否再发整段 token。
"""
import inspect
import logging
from collections.abc import Callable
from typing import Any

from langchain_openai import ChatOpenAI
from langchain_core.runnables.config import ensure_config
from langgraph.config import get_stream_writer

from src.core.config import get_settings

logger = logging.getLogger(__name__)


def normalize_message_content(content: Any) -> str:
    """将 AIMessage.content（str 或多模态 list）规范为纯文本。"""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict):
                if block.get("type") == "text":
                    parts.append(str(block.get("text", "")))
                elif "text" in block:
                    parts.append(str(block["text"]))
        return "".join(parts)
    return str(content)


def message_to_text(message: Any) -> str:
    """从 BaseMessage 取可见文本。"""
    if message is None:
        return ""
    return normalize_message_content(getattr(message, "content", None))


def extract_chunk_text(chunk: Any) -> str:
    """从 ChatModel 流式 chunk（如 AIMessageChunk）中提取用户可见文本增量。"""
    if chunk is None:
        return ""
    content = getattr(chunk, "content", None)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict):
                if block.get("type") == "text":
                    parts.append(str(block.get("text", "")))
                elif "text" in block:
                    parts.append(str(block["text"]))
        return "".join(parts)
    return ""


def _consume_astream_chunk(
    chunk: Any,
    token_cb: Callable[[str], None],
    streamed_flag: list[bool],
) -> dict[str, Any] | None:
    """解析 LangGraph astream 单帧；返回最后一帧 values 状态（若有）。"""
    last_values: dict[str, Any] | None = None

    def _emit(s: str) -> None:
        if s:
            streamed_flag[0] = True
            token_cb(s)

    # v2 统一流：{"type","ns","data",...}
    if isinstance(chunk, dict) and chunk.get("type") in ("messages", "values"):
        typ = chunk.get("type")
        data = chunk.get("data")
        if typ == "messages" and data is not None:
            msg = data[0] if isinstance(data, (tuple, list)) and len(data) >= 1 else data
            text = extract_chunk_text(msg)
            if text:
                _emit(text)
        elif typ == "values" and isinstance(data, dict):
            last_values = data
        return last_values

    # v1：("messages", (AIMessageChunk, meta)) 或 ("values", state_dict)
    if isinstance(chunk, tuple) and len(chunk) == 2:
        mode, data = chunk
        if mode == "messages" and data is not None:
            msg = data[0] if isinstance(data, (tuple, list)) and len(data) >= 1 else data
            text = extract_chunk_text(msg)
            if text:
                _emit(text)
        elif mode == "values" and isinstance(data, dict):
            last_values = data
        return last_values

    return None


async def invoke_react_agent_with_llm_stream(
    agent: Any,
    input_state: dict[str, Any],
    config: dict[str, Any] | None,
    token_cb: Callable[[str], None] | None,
) -> tuple[dict[str, Any], bool]:
    """与 ainvoke 同形输出；在 token_cb 非空时用 LangGraph astream(messages) 转发 LLM token。

    优先 astream(stream_mode=[\"messages\",\"values\"])：在图执行中注入 StreamMessagesHandler，
    比 astream_events 嵌套调用更可靠（尤其 create_react_agent + DashScope）。

    Returns:
        (result_dict, streamed_any): result_dict 含 messages；streamed_any 表示是否至少发出过一段可见文本。
    """
    if token_cb is None:
        out = await agent.ainvoke(input_state, config=config)
        return out, False

    streamed_flag = [False]
    # 子图单独 astream：不合并父 LangGraph 的 callbacks，避免与 messages 流式回调冲突
    cfg = ensure_config(config)

    astream_fn = getattr(agent, "astream", None)
    if astream_fn is not None:
        last_values: dict[str, Any] | None = None
        astream_kw: dict[str, Any] = {}
        try:
            sig = inspect.signature(astream_fn)
            if "version" in sig.parameters:
                astream_kw["version"] = "v1"
        except (TypeError, ValueError):
            pass
        try:
            async for chunk in astream_fn(
                input_state,
                config=cfg,
                stream_mode=["messages", "values"],
                **astream_kw,
            ):
                lv = _consume_astream_chunk(chunk, token_cb, streamed_flag)
                if lv is not None:
                    last_values = lv
        except Exception as e:
            logger.warning("astream(messages) 流式执行失败，回退 ainvoke: %s", e, exc_info=True)
            out = await agent.ainvoke(input_state, config=cfg)
            return out, False

        if last_values is not None and isinstance(last_values, dict) and "messages" in last_values:
            return last_values, streamed_flag[0]

        logger.warning("astream 未得到含 messages 的最终 values，回退 ainvoke")
        out = await agent.ainvoke(input_state, config=cfg)
        return out, streamed_flag[0]

    # 无 astream 时退回 astream_events
    stream_fn = getattr(agent, "astream_events", None)
    if stream_fn is None:
        out = await agent.ainvoke(input_state, config=cfg)
        return out, False

    last_with_messages: dict[str, Any] | None = None

    def _emit(s: str) -> None:
        if s:
            streamed_flag[0] = True
            token_cb(s)

    try:
        async for event in stream_fn(input_state, config=cfg, version="v2"):
            et = event.get("event") if isinstance(event, dict) else None
            if et == "on_chat_model_stream":
                data = event.get("data") if isinstance(event, dict) else None
                chunk = (data or {}).get("chunk") if isinstance(data, dict) else None
                text = extract_chunk_text(chunk)
                if text:
                    _emit(text)
            elif et == "on_llm_stream":
                data = event.get("data") if isinstance(event, dict) else None
                chunk = (data or {}).get("chunk") if isinstance(data, dict) else None
                if chunk is not None:
                    raw = getattr(chunk, "text", None)
                    text = raw if isinstance(raw, str) else extract_chunk_text(chunk)
                    if text:
                        _emit(text)
            elif et == "on_chain_end":
                data = event.get("data") if isinstance(event, dict) else None
                out = (data or {}).get("output") if isinstance(data, dict) else None
                if isinstance(out, dict) and "messages" in out:
                    last_with_messages = out
    except Exception as e:
        logger.warning("astream_events 流式执行失败，回退 ainvoke: %s", e, exc_info=True)
        out = await agent.ainvoke(input_state, config=cfg)
        return out, False

    if last_with_messages is not None:
        return last_with_messages, streamed_flag[0]

    logger.warning("astream_events 未捕获含 messages 的最终输出，回退 ainvoke")
    out = await agent.ainvoke(input_state, config=cfg)
    return out, streamed_flag[0]


def get_chat_model(
    max_tokens: int = 8192,
    temperature: float = 0.3,
    timeout: int | None = None,
    *,
    streaming: bool = False,
) -> ChatOpenAI:
    """创建 LangChain ChatOpenAI 实例（兼容 DashScope / Qwen API）。

    DashScope 在 enable_thinking=true 时需配合流式请求；此处通过 extra_body 关闭 thinking，
    可与 OpenAI 兼容接口的正常/流式调用并存。

    Args:
        streaming: 为 True 时，LangChain 在 ainvoke 路径上也会走底层流式 API（便于 astream_events
            产生 on_chat_model_stream）。DFIR 对话 Agent 建议开启；其它节点默认 False。
        timeout: LLM 单次请求超时秒数。默认用配置值；取证/样本等长任务可传更大值（如 180）。
    """
    settings = get_settings()
    return ChatOpenAI(
        model=settings.llm_model,
        api_key=settings.llm_api_key or "EMPTY",
        base_url=settings.llm_api_base or "https://dashscope.aliyuncs.com/compatible-mode/v1",
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout if timeout is not None else settings.llm_timeout_seconds,
        streaming=streaming,
        extra_body={"enable_thinking": False},
    )


def make_stream_helpers(
    state: dict, agent_name: str,
) -> tuple[Callable[..., None] | None, Callable[[str], None] | None]:
    """根据 state['use_streaming'] 返回 (writer, token_callback)。

    非流式模式或无流式上下文时返回 (None, None)。各智能体节点共享此函数。
    """
    if not state.get("use_streaming", False):
        return None, None
    try:
        writer = get_stream_writer()
    except RuntimeError:
        logger.debug("无法获取 stream_writer（可能不在 astream 上下文中），跳过流式输出")
        return None, None

    def token_cb(content: str) -> None:
        writer({"type": "token", "agent": agent_name, "content": content})

    return writer, token_cb
