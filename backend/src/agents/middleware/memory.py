"""
案件级长期记忆（跨 Session 共享）。

参考 DeepAgents MemoryMiddleware + AGENTS.md 机制。
存储路径: workspace/{case_id}/.case_memory.md
"""
import logging
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from filelock import FileLock

from src.core.config import get_settings

logger = logging.getLogger(__name__)

CASE_MEMORY_FILENAME = ".case_memory.md"
MEMORY_TEMPLATE = """---
## 案件概要
- 受害主机: （待补充）
- 攻击时间范围: （待补充）

## 已确认 IOC
（待补充）

## 分析进展
（待补充）

## 待验证假设
（待补充）
---
"""


def _case_memory_path(case_id: str) -> Path:
    """案件记忆文件路径。"""
    cid = (case_id or "").strip() or "_unknown"
    return get_settings().workspace_root_dir() / cid / CASE_MEMORY_FILENAME


def _case_memory_file_lock(path: Path) -> FileLock:
    """与 `.case_memory.md` 同目录下的互斥锁文件（跨进程）。"""
    return FileLock(str(path.parent / f"{CASE_MEMORY_FILENAME}.lock"), timeout=60)


@contextmanager
def _locked_case_memory(case_id: str):
    """对同一案件的读-改-写串行化，避免并行 tool call / 多 worker 丢失更新。"""
    path = _case_memory_path(case_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _case_memory_file_lock(path):
        yield path


def ensure_case_memory_template_if_missing(case_id: str) -> None:
    """若尚无 `.case_memory.md` 则写入模板（P2：创建案件或首次图执行前可调用）。"""
    if not case_id or not case_id.strip():
        return
    if not get_settings().case_memory_auto_init_enabled:
        return
    try:
        with _locked_case_memory(case_id) as path:
            if path.is_file():
                return
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(MEMORY_TEMPLATE, encoding="utf-8", newline="\n")
        logger.info("已初始化案件记忆模板: %s", case_id)
    except OSError as e:
        logger.warning("初始化案件记忆模板失败 %s: %s", case_id, e)


def load_case_memory(case_id: str) -> str:
    """
    加载案件级长期记忆。
    若启用自动初始化且文件不存在，会先创建模板再读取。
    """
    if not case_id or not case_id.strip():
        return ""
    ensure_case_memory_template_if_missing(case_id)
    path = _case_memory_path(case_id)
    if not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as e:
        logger.warning("加载案件记忆失败 %s: %s", case_id, e)
        return ""


def update_case_memory(case_id: str, content: str) -> dict[str, Any]:
    """
    完整覆盖写入案件记忆。
    若 content 为空则创建模板。
    """
    if not case_id or not case_id.strip():
        return {"ok": False, "error": "case_id 不能为空"}
    try:
        with _locked_case_memory(case_id) as path:
            text = content.strip() or MEMORY_TEMPLATE
            path.write_text(text, encoding="utf-8", newline="\n")
        return {"ok": True, "path": str(_case_memory_path(case_id))}
    except Exception as e:
        logger.warning("写入案件记忆失败 %s: %s", case_id, e)
        return {"ok": False, "error": str(e)}


def extract_case_memory_section(text: str, section: str) -> str:
    """返回 `## {section}` 章节全文（含标题行），至下一 `##` 行或分隔 `---` 之前。"""
    sec = (section or "").strip()
    if not sec:
        return ""
    section_header = f"## {sec}"
    if section_header not in text:
        return ""
    idx = text.find(section_header)
    after = text[idx + len(section_header) :]
    next_h2 = after.find("\n## ")
    next_delim = after.find("\n---")
    end = len(after)
    if next_h2 >= 0 and (next_delim < 0 or next_h2 < next_delim):
        end = next_h2
    elif next_delim >= 0:
        end = next_delim
    body = after[:end].strip()
    return f"{section_header}\n{body}"


def append_case_memory(
    case_id: str,
    section: str,
    content: str,
    session_id: str = "",
) -> dict[str, Any]:
    """
    向案件记忆追加内容。
    section: 章节名，如 "分析进展"、"已确认 IOC"
    content: 追加的 Markdown 内容
    session_id: 可选，用于标注来源
    """
    if not case_id or not case_id.strip():
        return {"ok": False, "error": "case_id 不能为空"}
    sec = (section or "").strip()
    if not sec:
        return {"ok": False, "error": "section 不能为空"}

    try:
        with _locked_case_memory(case_id) as path:
            existing = ""
            if path.is_file():
                existing = path.read_text(encoding="utf-8").replace("\r\n", "\n")
            else:
                existing = MEMORY_TEMPLATE

            timestamp = datetime.now().strftime("%Y-%m-%d")
            session_tag = f" sess-{session_id}" if session_id else ""
            new_entry = f"- [{timestamp}{session_tag}] {content.strip()}\n"

            section_header = f"## {sec}"
            if section_header in existing:
                # 在章节内追加：找到 ## Section 后、下一个 ## 或 --- 前
                idx = existing.find(section_header)
                if idx >= 0:
                    after_header = existing[idx + len(section_header) :]
                    next_h2 = after_header.find("\n## ")
                    next_delim = after_header.find("\n---")
                    end = len(after_header)
                    if next_h2 >= 0 and (next_delim < 0 or next_h2 < next_delim):
                        end = next_h2 + 1
                    elif next_delim >= 0:
                        end = next_delim + 1
                    insert_pos = idx + len(section_header) + end
                    new_content = (
                        existing[:insert_pos].rstrip() + "\n" + new_entry + existing[insert_pos:]
                    )
                else:
                    new_content = existing.rstrip() + f"\n\n{section_header}\n{new_entry}"
            else:
                new_content = existing.rstrip() + f"\n\n{section_header}\n{new_entry}"

            path.write_text(new_content, encoding="utf-8", newline="\n")
        return {"ok": True, "path": str(_case_memory_path(case_id))}
    except Exception as e:
        logger.warning("追加案件记忆失败 %s: %s", case_id, e)
        return {"ok": False, "error": str(e)}
