"""
统一 ID 生成与格式校验。
所有实体 ID 格式: {prefix}-{12位十六进制}
  案件   case-93d4e4c82dec
  会话   session-453e082cff8a
  证据   ev-52598b8403a8
  报告   report-7f3a1b2c4d5e
  消息   msg-a1b2c3d4e5f6
"""
import re
import uuid

PREFIX_CASE = "case"
PREFIX_SESSION = "session"
PREFIX_EVIDENCE = "ev"
PREFIX_REPORT = "report"
PREFIX_MESSAGE = "msg"

_HEX_LEN = 12
_ID_RE = re.compile(r"^[a-z]+-[0-9a-f]{12}$")

_PREFIX_PATTERNS: dict[str, re.Pattern] = {
    PREFIX_CASE: re.compile(r"^case-[0-9a-f]{12}$"),
    PREFIX_SESSION: re.compile(r"^session-[0-9a-f]{12}$"),
    PREFIX_EVIDENCE: re.compile(r"^ev-[0-9a-f]{12}$"),
    PREFIX_REPORT: re.compile(r"^report-[0-9a-f]{12}$"),
    PREFIX_MESSAGE: re.compile(r"^msg-[0-9a-f]{12}$"),
}


def generate_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:_HEX_LEN]}"


def new_case_id() -> str:
    return generate_id(PREFIX_CASE)


def new_session_id() -> str:
    return generate_id(PREFIX_SESSION)


def new_evidence_id() -> str:
    return generate_id(PREFIX_EVIDENCE)


def new_report_id() -> str:
    return generate_id(PREFIX_REPORT)


def new_message_id() -> str:
    return generate_id(PREFIX_MESSAGE)


def is_valid_id(value: str, prefix: str | None = None) -> bool:
    """校验 ID 格式。prefix 为 None 时仅校验通用格式。"""
    if not value:
        return False
    if prefix and prefix in _PREFIX_PATTERNS:
        return bool(_PREFIX_PATTERNS[prefix].match(value))
    return bool(_ID_RE.match(value))
