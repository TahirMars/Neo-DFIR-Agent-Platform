"""
报告路由：生成、列表、预览、下载、批量下载、更新、删除。RBAC。
"""
import io
import logging
import re
import zipfile
from datetime import date
from typing import Annotated
from urllib.parse import quote

logger = logging.getLogger(__name__)

from fastapi import APIRouter, Body, Depends
from fastapi.responses import PlainTextResponse, Response

from src.api.deps import validate_report_id, validate_session_id
from src.core.auth import ensure_case_access, ensure_session_access, require_permission
from src.core.exceptions import CODE_NOT_FOUND, NeoException
from src.tools.evidence.tools import session_artifacts_get
from src.models.user import Permission, Role, User
from src.services.report_store import (
    create_report as store_create_report,
    delete_report as store_delete_report,
    get_report as store_get_report,
    list_reports_by_session,
    list_reports_by_user,
    update_report as store_update_report,
)
from src.services.session_store import (
    get_case as store_get_case,
    get_session,
    list_session_messages,
)

router = APIRouter(tags=["报告"])


def _sanitize_filename_part(s: str, max_len: int = 50) -> str:
    """文件名安全化：替换非法字符，截断长度。"""
    if not s or not isinstance(s, str):
        return "report"
    s = re.sub(r'[/\\:*?"<>|]', "_", s.strip())[:max_len]
    return s or "report"


def _report_download_basename(case_name: str, case_id: str, session_id: str) -> str:
    """生成下载文件名：[案件名称]_[案件ID]_[会话ID]_report_[当前日期]"""
    cn = _sanitize_filename_part(case_name or "未命名案件", 40)
    cid = _sanitize_filename_part(case_id, 20)
    sid = _sanitize_filename_part(session_id, 20)
    today = date.today().strftime("%Y%m%d")
    return f"{cn}_{cid}_{sid}_report_{today}"


def _content_disposition_filename(title: str, ext: str, fallback: str = "report") -> str:
    """生成支持中文的 Content-Disposition 头（RFC 5987）。"""
    safe = (title or fallback).replace("/", "_")[:50].strip()
    ascii_fallback = "".join(c for c in safe if ord(c) < 128) or fallback
    ascii_fallback = f"{ascii_fallback}.{ext}"
    if all(ord(c) < 128 for c in safe):
        return f'attachment; filename="{ascii_fallback}"'
    encoded = quote(f"{safe}.{ext}", safe="")
    return f'attachment; filename="{ascii_fallback}"; filename*=UTF-8\'\'{encoded}'


def _build_report_content_from_messages(session_id: str) -> str:
    """从会话消息汇总生成报告内容（合并所有 assistant 回复）。"""
    messages = list_session_messages(session_id)
    parts = []
    for m in messages:
        if (m.get("role") or "").lower() == "assistant":
            content = (m.get("content") or "").strip()
            if content:
                parts.append(content)
    return "\n\n---\n\n".join(parts) if parts else ""


_pdf_fonts_ready = False
_pdf_font_family = "Helvetica"


def _init_pdf_fonts() -> None:
    """向 reportlab 注册中文字体，确保 xhtml2pdf 能正确渲染中文。

    优先使用系统 TTF 字体（Windows: 微软雅黑/宋体; Linux: Noto CJK），
    回退到 reportlab 内置 CID 字体 STSong-Light。
    """
    global _pdf_fonts_ready, _pdf_font_family
    if _pdf_fonts_ready:
        return
    _pdf_fonts_ready = True

    import os
    import platform
    from pathlib import Path

    from reportlab.pdfbase import pdfmetrics

    # --- 策略 1：系统 TTF/TTC 字体 ---
    from reportlab.pdfbase.ttfonts import TTFont

    candidates: list[tuple[str, Path, int | None]] = []
    if platform.system() == "Windows":
        fd = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "Fonts"
        candidates = [
            ("MicrosoftYaHei", fd / "msyh.ttc", 0),
            ("SimSun", fd / "simsun.ttc", 0),
            ("SimHei", fd / "simhei.ttf", None),
        ]
    else:
        for p in (
            Path("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"),
            Path("/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc"),
            Path("/usr/share/fonts/truetype/noto/NotoSansSC-Regular.ttf"),
        ):
            candidates.append(("NotoSansSC", p, 0 if p.suffix == ".ttc" else None))

    for name, path, sub_idx in candidates:
        if path.exists():
            try:
                kw = {"subfontIndex": sub_idx} if sub_idx is not None else {}
                pdfmetrics.registerFont(TTFont(name, str(path), **kw))
                _pdf_font_family = name
                logger.info("PDF 中文字体已注册: %s (%s)", name, path)
                return
            except Exception as exc:
                logger.debug("TTF 字体 %s 注册失败: %s", name, exc)

    # --- 策略 2：reportlab 内置 CID 字体 ---
    try:
        from reportlab.pdfbase.cidfonts import UnicodeCIDFont
        pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
        _pdf_font_family = "STSong-Light"
        logger.info("PDF 中文字体已注册: STSong-Light (CID)")
        return
    except Exception as exc:
        logger.debug("CID 字体注册失败: %s", exc)

    logger.warning("未找到可用中文字体，PDF 中文可能显示异常")


# Emoji / 特殊 Unicode → 纯文本替换表（xhtml2pdf + TTF 字体无法渲染 Emoji）
_EMOJI_MAP: dict[str, str] = {
    "\U0001f4ca": "[图]",    # 📊
    "\U0001f4cb": "[表]",    # 📋
    "\U0001f4ac": "[话]",    # 💬
    "\U0001f4cc": "[钉]",    # 📌
    "\U0001f4cd": "[位]",    # 📍
    "\U0001f310": "[网]",    # 🌐
    "\U0001f512": "[锁]",    # 🔒
    "\U0001f513": "[开]",    # 🔓
    "\U0001f50d": "[搜]",    # 🔍
    "\U0001f6a8": "[警]",    # 🚨
    "\U0001f6e1": "[盾]",    # 🛡
    "\u26a0\ufe0f": "[!]",   # ⚠️
    "\u26a0": "[!]",          # ⚠
    "\u2705": "[v]",          # ✅
    "\u274c": "[x]",          # ❌
    "\u2139\ufe0f": "[i]",   # ℹ️
    "\u2139": "[i]",          # ℹ
    "\U0001f4a1": "[提示]",  # 💡
    "\U0001f4e6": "[包]",    # 📦
    "\U0001f4c1": "[目录]",  # 📁
    "\U0001f4c4": "[文件]",  # 📄
    "\U0001f9ec": "[DNA]",   # 🧬
    "\U0001f3af": "[目标]",  # 🎯
    "\U0001f525": "[火]",    # 🔥
    "\u2b06\ufe0f": "[上]",  # ⬆️
    "\u2b07\ufe0f": "[下]",  # ⬇️
    "\u27a1\ufe0f": "->",    # ➡️
    "\u2022": "*",            # •（某些字体不支持）
}


def _strip_emoji(text: str) -> str:
    """将 Emoji 和不可渲染的 Unicode 符号替换为纯文本等价物。"""
    for emoji, replacement in _EMOJI_MAP.items():
        text = text.replace(emoji, replacement)
    # 移除残余的 Emoji / Supplementary Plane 字符（U+1F000-U+1FFFF, U+2600-U+27BF 等）
    import re as _re
    text = _re.sub(
        r'[\U0001F000-\U0001FFFF\U00002600-\U000027BF\U0000FE00-\U0000FE0F\U000E0020-\U000E007F]',
        '',
        text,
    )
    return text


def _render_mermaid_png(code: str) -> bytes | None:
    """通过 mermaid.ink 在线服务将 Mermaid 代码渲染为 PNG 图片。"""
    import base64 as b64mod
    import html as htmlmod
    import json as jsonmod
    import urllib.request

    code = htmlmod.unescape(code)

    payload = jsonmod.dumps({
        "code": code,
        "mermaid": {"theme": "default"},
    }, ensure_ascii=False)
    encoded = b64mod.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii")
    url = f"https://mermaid.ink/img/base64:{encoded}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Neo-DFIR/1.0"})
        with urllib.request.urlopen(req, timeout=25) as resp:
            if resp.status == 200:
                data = resp.read()
                if len(data) > 200:
                    return data
    except Exception as exc:
        logger.debug("mermaid.ink 渲染失败: %s", exc)
    return None


def _preprocess_mermaid_blocks(html: str) -> str:
    """将 Mermaid 代码块渲染为图片嵌入 HTML；渲染失败时降级为代码展示。"""
    import base64 as b64mod
    import re as _re

    pattern = _re.compile(
        r'<pre><code class="language-mermaid">(.*?)</code></pre>',
        _re.DOTALL,
    )

    def _replace(m: _re.Match) -> str:
        raw = m.group(1).strip()
        png = _render_mermaid_png(raw)
        if png:
            b64 = b64mod.b64encode(png).decode("ascii")
            return (
                '<div class="mermaid-img">'
                f'<img src="data:image/png;base64,{b64}" />'
                '</div>'
            )
        # 降级：显示为格式化代码块
        return f'<pre class="mermaid-code">{raw}</pre>'

    return pattern.sub(_replace, html)


def _fix_list_bullets(html: str) -> str:
    """将 <ul> 的项目符号替换为纯文本标记，避免 xhtml2pdf 字体缺失导致乱码。

    xhtml2pdf 内部用字体字形渲染 disc/circle/square 项目符号，
    但注册的中文 TTF 字体往往缺少这些字形。本函数将 <ul> 切换为
    list-style-type:none 并在 <li> 前插入文本标记。
    """
    import re as _re

    parts = _re.split(r"(</?(?:ul|ol)(?:\s[^>]*)?>)", html)
    ul_depth = 0
    result: list[str] = []
    for part in parts:
        if _re.match(r"<ul[\s>]", part):
            ul_depth += 1
            result.append(part)
        elif part.startswith("</ul"):
            ul_depth = max(ul_depth - 1, 0)
            result.append(part)
        else:
            if ul_depth > 0:
                part = part.replace("<li>", "<li>- ")
            result.append(part)
    return "".join(result)


def _markdown_to_pdf(md_content: str) -> bytes | None:
    """将 Markdown 转为高质量 PDF，支持中文、表格、代码块、Mermaid 占位。"""
    try:
        import io as iolib
        import markdown as md_lib
        from xhtml2pdf import pisa

        _init_pdf_fonts()
        font = _pdf_font_family

        # 清理 Emoji 和不可渲染字符（必须在 markdown 转换前处理）
        md_content = _strip_emoji(md_content)

        html_body = md_lib.markdown(
            md_content,
            extensions=["tables", "fenced_code", "nl2br", "toc", "sane_lists"],
        )
        html_body = _preprocess_mermaid_blocks(html_body)
        html_body = _fix_list_bullets(html_body)

        html_doc = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<style>
/* ========== 基础排版 ========== */
@page {{
    size: A4;
    margin: 2cm 2.2cm;
    @frame footer {{
        -pdf-frame-content: page-footer;
        bottom: 0.5cm;
        height: 1cm;
        margin-left: 2.2cm;
        margin-right: 2.2cm;
    }}
}}
body {{
    font-family: "{font}", "STSong-Light", "SimSun", "Microsoft YaHei", sans-serif;
    font-size: 11pt;
    line-height: 1.7;
    color: #1a1a1a;
    -pdf-word-wrap: CJK;
}}

/* ========== 标题 ========== */
h1 {{
    font-size: 20pt;
    font-weight: bold;
    color: #111827;
    margin: 0 0 12pt 0;
    padding-bottom: 6pt;
    border-bottom: 2px solid #4f46e5;
}}
h2 {{
    font-size: 15pt;
    font-weight: bold;
    color: #1f2937;
    margin: 20pt 0 8pt 0;
    padding-bottom: 4pt;
    border-bottom: 1px solid #d1d5db;
}}
h3 {{
    font-size: 12pt;
    font-weight: bold;
    color: #374151;
    margin: 14pt 0 6pt 0;
}}
h4 {{
    font-size: 11pt;
    font-weight: bold;
    color: #4b5563;
    margin: 10pt 0 4pt 0;
}}

/* ========== 段落与列表 ========== */
p {{ margin: 0 0 8pt 0; }}
ul {{ margin: 4pt 0 8pt 0; padding-left: 16pt; list-style-type: none; }}
ol {{ margin: 4pt 0 8pt 0; padding-left: 20pt; }}
li {{ margin-bottom: 3pt; }}
strong {{ color: #111827; }}
em {{ font-style: italic; }}
a {{ color: #4f46e5; text-decoration: underline; }}
hr {{ border: none; border-top: 1px solid #e5e7eb; margin: 14pt 0; }}

/* ========== 表格 ========== */
table {{
    width: 100%;
    border-collapse: collapse;
    margin: 10pt 0;
    font-size: 9.5pt;
    -pdf-keep-in-frame-mode: shrink;
}}
th {{
    background-color: #f3f4f6;
    color: #111827;
    font-weight: bold;
    padding: 6pt 8pt;
    border: 1px solid #d1d5db;
    text-align: left;
}}
td {{
    padding: 5pt 8pt;
    border: 1px solid #e5e7eb;
    color: #374151;
    vertical-align: top;
}}
tr:nth-child(even) td {{
    background-color: #f9fafb;
}}

/* ========== 代码 ========== */
code {{
    font-family: "Courier", monospace;
    font-size: 9pt;
    background-color: #f3f4f6;
    padding: 1pt 4pt;
    border-radius: 2pt;
    color: #1f2937;
}}
pre {{
    background-color: #f3f4f6;
    border: 1px solid #e5e7eb;
    border-radius: 4pt;
    padding: 10pt 12pt;
    margin: 8pt 0;
    font-family: "Courier", monospace;
    font-size: 8.5pt;
    line-height: 1.5;
    white-space: pre-wrap;
    word-wrap: break-word;
    -pdf-word-wrap: CJK;
}}
pre code {{
    background: none;
    padding: 0;
    font-size: inherit;
}}

/* ========== 引用块 ========== */
blockquote {{
    margin: 8pt 0;
    padding: 8pt 12pt;
    border-left: 3pt solid #4f46e5;
    background-color: #f5f3ff;
    color: #4b5563;
}}
blockquote p {{
    margin: 0;
}}

/* ========== Mermaid 图片 ========== */
.mermaid-img {{
    margin: 12pt 0;
    text-align: center;
}}
.mermaid-img img {{
    max-width: 100%;
    height: auto;
}}
.mermaid-code {{
    background-color: #f3f4f6;
    border: 1px solid #e5e7eb;
    font-size: 8pt;
    color: #374151;
}}

/* ========== 页脚 ========== */
#page-footer {{
    font-size: 8pt;
    color: #9ca3af;
    text-align: center;
}}
</style>
</head>
<body>
{html_body}
<div id="page-footer">
    Neo DFIR 多智能体分析平台
</div>
</body></html>"""

        buf = iolib.BytesIO()
        status = pisa.CreatePDF(html_doc, dest=buf, encoding="utf-8")
        if status.err:
            logger.error("xhtml2pdf 生成 PDF 失败: err=%s", status.err)
            return None
        return buf.getvalue()
    except Exception:
        logger.exception("_markdown_to_pdf 异常")
        return None


# ===================== 生成报告 =====================


@router.post("/sessions/{session_id}/reports")
def generate_report(
    session_id: Annotated[str, Depends(validate_session_id)],
    current_user: Annotated[User, Depends(require_permission(Permission.report_read))],
    body: dict = Body(default_factory=dict),
):
    """从历史聊天汇总生成报告并持久化。"""
    sess = get_session(session_id)
    if not sess:
        raise NeoException(status_code=404, message="会话不存在", code=CODE_NOT_FOUND)
    ensure_session_access(current_user, sess, store_get_case)
    case_id = sess.get("case_id") or ""
    content = _build_report_content_from_messages(session_id)
    if not content.strip():
        raise NeoException(status_code=400, message="暂无对话内容，请先与 AI 对话后再生成报告", code="invalid_input")
    title = (body.get("title") or "").strip() or "分析报告"
    report = store_create_report(
        session_id=session_id,
        case_id=case_id,
        content=content,
        title=title,
    )
    return {"ok": True, "report": report}


# ===================== 报告列表 =====================


@router.get("/sessions/{session_id}/reports")
def list_session_reports(
    session_id: Annotated[str, Depends(validate_session_id)],
    current_user: Annotated[User, Depends(require_permission(Permission.report_read))],
):
    """会话下的报告列表。"""
    sess = get_session(session_id)
    if not sess:
        raise NeoException(status_code=404, message="会话不存在", code=CODE_NOT_FOUND)
    ensure_session_access(current_user, sess, store_get_case)
    items = list_reports_by_session(session_id)
    return {"session_id": session_id, "items": items, "total": len(items)}


@router.get("/reports")
def list_my_reports(
    current_user: Annotated[User, Depends(require_permission(Permission.report_read))],
):
    """我的报告：跨案件、会话的汇总列表。"""
    user_id = current_user.id
    is_admin = current_user.role == Role.admin
    items = list_reports_by_user(user_id, is_admin=is_admin)
    # 补充案件名、会话信息
    case_cache = {}
    for r in items:
        cid = r.get("case_id")
        if cid and cid not in case_cache:
            case_cache[cid] = store_get_case(cid)
        c = case_cache.get(cid) or {}
        r["case_name"] = c.get("name") or "未命名案件"
    return {"items": items, "total": len(items)}


# ===================== 单条报告 CRUD =====================


@router.get("/sessions/{session_id}/reports/{report_id}")
def get_report_detail(
    session_id: Annotated[str, Depends(validate_session_id)],
    report_id: Annotated[str, Depends(validate_report_id)],
    current_user: Annotated[User, Depends(require_permission(Permission.report_read))],
):
    """获取单条报告（预览）。"""
    sess = get_session(session_id)
    if not sess:
        raise NeoException(status_code=404, message="会话不存在", code=CODE_NOT_FOUND)
    ensure_session_access(current_user, sess, store_get_case)
    report = store_get_report(report_id)
    if not report or report.get("session_id") != session_id:
        raise NeoException(status_code=404, message="报告不存在", code=CODE_NOT_FOUND)
    return report


@router.put("/sessions/{session_id}/reports/{report_id}")
def update_report(
    session_id: Annotated[str, Depends(validate_session_id)],
    report_id: Annotated[str, Depends(validate_report_id)],
    current_user: Annotated[User, Depends(require_permission(Permission.report_read))],
    body: dict = Body(default_factory=dict),
):
    """更新报告（标题、内容）。"""
    sess = get_session(session_id)
    if not sess:
        raise NeoException(status_code=404, message="会话不存在", code=CODE_NOT_FOUND)
    ensure_session_access(current_user, sess, store_get_case)
    report = store_get_report(report_id)
    if not report or report.get("session_id") != session_id:
        raise NeoException(status_code=404, message="报告不存在", code=CODE_NOT_FOUND)
    title = body.get("title")
    content = body.get("content")
    updated = store_update_report(report_id, title=title, content=content)
    return {"ok": True, "report": updated}


@router.delete("/sessions/{session_id}/reports/{report_id}")
def delete_report(
    session_id: Annotated[str, Depends(validate_session_id)],
    report_id: Annotated[str, Depends(validate_report_id)],
    current_user: Annotated[User, Depends(require_permission(Permission.report_read))],
):
    """删除报告。"""
    sess = get_session(session_id)
    if not sess:
        raise NeoException(status_code=404, message="会话不存在", code=CODE_NOT_FOUND)
    ensure_session_access(current_user, sess, store_get_case)
    report = store_get_report(report_id)
    if not report or report.get("session_id") != session_id:
        raise NeoException(status_code=404, message="报告不存在", code=CODE_NOT_FOUND)
    store_delete_report(report_id)
    return {"ok": True, "report_id": report_id}


# ===================== 下载 =====================


@router.get("/sessions/{session_id}/reports/{report_id}/download")
def download_report(
    session_id: Annotated[str, Depends(validate_session_id)],
    report_id: Annotated[str, Depends(validate_report_id)],
    current_user: Annotated[User, Depends(require_permission(Permission.report_read))],
    format: str = "md",
):
    """下载单条报告（PDF 或 Markdown）。"""
    sess = get_session(session_id)
    if not sess:
        raise NeoException(status_code=404, message="会话不存在", code=CODE_NOT_FOUND)
    ensure_session_access(current_user, sess, store_get_case)
    report = store_get_report(report_id)
    if not report or report.get("session_id") != session_id:
        raise NeoException(status_code=404, message="报告不存在", code=CODE_NOT_FOUND)
    content = report.get("content") or ""
    case_id = report.get("case_id") or ""
    case = store_get_case(case_id) if case_id else {}
    case_name = case.get("name") or "未命名案件"
    base_name = _report_download_basename(case_name, case_id, session_id)
    ext = "pdf" if format == "pdf" else "md"
    fallback = f"{case_id}_{session_id[:12]}_report_{date.today().strftime('%Y%m%d')}"
    if format == "pdf":
        pdf_bytes = _markdown_to_pdf(content)
        if not pdf_bytes:
            raise NeoException(status_code=500, message="PDF 生成失败", code="pdf_generation_failed")
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": _content_disposition_filename(base_name, "pdf", fallback)},
        )
    return PlainTextResponse(
        content,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": _content_disposition_filename(base_name, "md", fallback)},
    )


@router.post("/reports/batch-download")
def batch_download_reports(
    current_user: Annotated[User, Depends(require_permission(Permission.report_read))],
    body: dict = Body(default_factory=dict),
):
    """批量下载报告（ZIP）。body: {report_ids: [], format: "pdf"|"md"}"""
    report_ids = body.get("report_ids") or []
    fmt = (body.get("format") or "md").lower()
    if fmt not in ("pdf", "md"):
        fmt = "md"
    if not report_ids:
        raise NeoException(status_code=400, message="report_ids 不能为空", code="invalid_input")

    # 校验权限：获取用户有权限的报告
    is_admin = current_user.role == Role.admin
    my_reports = list_reports_by_user(current_user.id, is_admin=is_admin)
    my_ids = {r["id"] for r in my_reports}
    my_map = {r["id"]: r for r in my_reports}
    valid_ids = [rid for rid in report_ids if rid in my_ids]
    if not valid_ids:
        raise NeoException(status_code=400, message="无有效报告可下载", code="invalid_input")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for rid in valid_ids:
            r = my_map[rid]
            content = r.get("content") or ""
            case_id = r.get("case_id") or ""
            session_id = r.get("session_id") or ""
            case_name = r.get("case_name")
            if case_name is None and case_id:
                c = store_get_case(case_id)
                case_name = c.get("name") if c else "未命名案件"
            case_name = case_name or "未命名案件"
            base_name = _report_download_basename(case_name, case_id, session_id)
            ext = "pdf" if fmt == "pdf" else "md"
            fname = f"{base_name}.{ext}"
            if fmt == "pdf":
                pdf_bytes = _markdown_to_pdf(content)
                if pdf_bytes:
                    zf.writestr(fname, pdf_bytes)
            else:
                zf.writestr(fname, content.encode("utf-8"))

    buf.seek(0)
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="reports.zip"'},
    )


# ===================== 兼容旧接口：会话级报告（无 report_id 时从消息或 artifact） =====================


def _build_legacy_report_data(session_id: str) -> dict:
    """从 artifact 或消息构建报告数据（兼容旧版）。"""
    sess = get_session(session_id)
    if not sess:
        return {"markdown": "", "evidence_refs": [], "source": "chat"}
    aid = sess.get("report_artifact_id")
    if aid:
        envelope = session_artifacts_get(session_id, aid)
        if envelope.get("ok") and envelope.get("data"):
            data = envelope["data"].get("json") or {}
            data.setdefault("source", "pipeline")
            return data
    content = _build_report_content_from_messages(session_id)
    return {
        "markdown": content or "# 暂无报告内容\n\n请先与 AI 对话进行分析，或点击「生成报告」汇总。",
        "evidence_refs": [],
        "source": "chat",
    }


@router.get("/sessions/{session_id}/report")
def get_report_legacy(
    session_id: Annotated[str, Depends(validate_session_id)],
    current_user: Annotated[User, Depends(require_permission(Permission.report_read))],
    format: str = "md",
):
    """兼容旧接口：会话级报告（无 report_id 时从消息或 artifact）。"""
    sess = get_session(session_id)
    if not sess:
        raise NeoException(status_code=404, message="会话不存在", code=CODE_NOT_FOUND)
    ensure_session_access(current_user, sess, store_get_case)
    data = _build_legacy_report_data(session_id)
    markdown = data.get("markdown") or ""
    if format == "json":
        return {"session_id": session_id, "format": "json", "data": data}
    if format == "pdf":
        pdf_bytes = _markdown_to_pdf(markdown)
        if pdf_bytes:
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={"Content-Disposition": f'attachment; filename="report_{session_id[:16]}.pdf"'},
            )
        raise NeoException(status_code=500, message="PDF 生成失败", code="pdf_generation_failed")
    return PlainTextResponse(
        markdown,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="report_{session_id[:16]}.md"'},
    )
