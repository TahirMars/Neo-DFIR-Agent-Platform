"""
统一异常与错误响应（code / message / details）。
与设计 2.1 一致：错误响应 { "code", "message", "details" }。
"""
import uuid
from typing import Any, Optional

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse


# 业务错误码（与 HTTP 状态码分离）
CODE_UNAUTHORIZED = "UNAUTHORIZED"
CODE_FORBIDDEN = "FORBIDDEN"
CODE_NOT_FOUND = "NOT_FOUND"
CODE_BAD_REQUEST = "BAD_REQUEST"
CODE_CONFLICT = "CONFLICT"
CODE_INTERNAL = "INTERNAL_ERROR"


class NeoException(HTTPException):
    """Neo 业务异常基类；可带 code、details。"""

    def __init__(
        self,
        status_code: int = 400,
        message: str = "请求错误",
        code: str = CODE_BAD_REQUEST,
        details: Optional[dict[str, Any]] = None,
    ):
        super().__init__(status_code=status_code, detail=message)
        self.code = code
        self.details = details or {}


def error_response(status_code: int, message: str, code: str, details: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """统一错误响应体。"""
    return {"code": code, "message": message, "details": details}


async def neo_exception_handler(request: Request, exc: NeoException) -> JSONResponse:
    """NeoException 转为 JSON 响应。"""
    return JSONResponse(
        status_code=exc.status_code,
        content=error_response(exc.status_code, exc.detail, getattr(exc, "code", CODE_BAD_REQUEST), getattr(exc, "details", None)),
    )


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """HTTPException 转为统一格式。"""
    code = CODE_BAD_REQUEST
    if exc.status_code == 401:
        code = CODE_UNAUTHORIZED
    elif exc.status_code == 403:
        code = CODE_FORBIDDEN
    elif exc.status_code == 404:
        code = CODE_NOT_FOUND
    elif exc.status_code >= 500:
        code = CODE_INTERNAL
    detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
    return JSONResponse(
        status_code=exc.status_code,
        content=error_response(exc.status_code, detail, code, None),
    )


def generate_request_id() -> str:
    """生成请求 ID（无传入时由中间件使用）。"""
    return uuid.uuid4().hex[:16]
