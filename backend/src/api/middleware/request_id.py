"""
请求 ID 中间件：从 X-Request-Id 读取或生成，写入 request.state 并随响应头返回。
与设计 2.1 一致：贯穿编排器与 MCP 调用，用于链路追踪与审计。
"""
import uuid
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

REQUEST_ID_HEADER = "X-Request-Id"
REQUEST_ID_STATE_KEY = "request_id"


def get_request_id(request: Request) -> str:
    """从 request.state 取请求 ID（中间件注入后可用）。"""
    return getattr(request.state, REQUEST_ID_STATE_KEY, "") or ""


class RequestIDMiddleware(BaseHTTPMiddleware):
    """注入或生成 X-Request-Id，写入 request.state.request_id。"""

    async def dispatch(self, request: Request, call_next: callable) -> Response:
        raw = request.headers.get(REQUEST_ID_HEADER)
        request_id = (raw and raw.strip()) or uuid.uuid4().hex[:16]
        setattr(request.state, REQUEST_ID_STATE_KEY, request_id)
        response = await call_next(request)
        response.headers[REQUEST_ID_HEADER] = request_id
        return response
