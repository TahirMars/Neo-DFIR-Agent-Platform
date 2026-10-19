"""
证据管理工具层：
- session_create: 创建会话（通过 session_store）
- evidence_ingest: 证据包暂存 → 解压校验 → 原子移入证据区
- get_evidence_manifest: 获取证据清单
- session_artifacts_get: 获取会话 artifact
- delete_evidence_for_case: 删除案件关联的全部证据
- read_evidence_file: 读取证据包内指定文件
- classify_evidence_files: 对证据包内文件进行类型分类

存储结构:
  data/evidence/{case_id}/{ev_id}/{original_filename}
                                 /uploads/...          (ZIP 解压内容)
                                 /manifest.json
"""
import hashlib
import json
import os
import shutil
import zipfile
from pathlib import Path
from typing import Any

from src.core.config import get_settings
from src.core.ids import new_evidence_id

_manifests: dict[str, dict[str, Any]] = {}
_artifacts: dict[str, dict[str, Any]] = {}  # key = f"{session_id}:{artifact_id}"
_evidence_case_map: dict[str, str] = {}  # evidence_id -> case_id

BINARY_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".bin", ".elf", ".so", ".dylib",
    ".msi", ".scr", ".com", ".ocx", ".cpl", ".drv",
    ".iso", ".img", ".vhd", ".vmdk",
    ".doc", ".xls", ".ppt", ".docx", ".xlsx", ".pptx",
    ".pdf", ".rtf", ".jar", ".class", ".apk",
    ".7z", ".rar", ".cab", ".gz", ".tar", ".bz2",
}

LOG_EXTENSIONS = {
    ".csv", ".json", ".jsonl", ".log", ".txt", ".xml",
    ".evtx", ".evt", ".etl",
    ".html", ".htm", ".yaml", ".yml", ".ini", ".cfg", ".conf",
    ".md", ".rst",
}


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _resolve_evidence_dir(evidence_id: str) -> Path | None:
    """
    根据 evidence_id 解析其在磁盘上的实际目录。
    路径格式: evidence_storage_dir / {case_id} / {evidence_id}
    优先从内存映射查找 case_id，回退到磁盘扫描。
    """
    settings = get_settings()
    base = settings.evidence_storage_dir()
    case_id = _evidence_case_map.get(evidence_id)
    if case_id:
        d = base / case_id / evidence_id
        if d.is_dir():
            return d
    if not base.is_dir():
        return None
    for case_dir in base.iterdir():
        if case_dir.is_dir():
            ev_dir = case_dir / evidence_id
            if ev_dir.is_dir():
                _evidence_case_map[evidence_id] = case_dir.name
                return ev_dir
    return None


def session_create(params: dict[str, Any]) -> dict[str, Any]:
    """创建会话，返回 { ok, data: { session_id } }。"""
    from src.services.session_store import create_session
    case_id = params.get("case_id", "")
    if not case_id:
        return {"ok": False, "errors": ["case_id 不能为空"]}
    try:
        sess = create_session(case_id)
        return {"ok": True, "data": {"session_id": sess["id"]}}
    except Exception as e:
        return {"ok": False, "errors": [str(e)]}


def evidence_ingest(
    case_id: str,
    session_id: str,
    staging_path: str,
    original_filename: str = "evidence.zip",
) -> dict[str, Any]:
    """
    从暂存路径 ingest 证据包：
    1. 生成 ev-xxx evidence_id
    2. 保存原始文件并解压到 evidence_storage / {case_id} / {ev_id} /
    3. 生成 manifest.json
    """
    settings = get_settings()
    evidence_dir = settings.evidence_storage_dir()

    if not os.path.isfile(staging_path):
        return {"ok": False, "errors": [f"暂存文件不存在: {staging_path}"]}

    evidence_id = new_evidence_id()
    dest = evidence_dir / case_id / evidence_id
    dest.mkdir(parents=True, exist_ok=True)

    sha256 = _sha256_file(staging_path)

    manifest: dict[str, Any] = {
        "evidence_id": evidence_id,
        "case_id": case_id,
        "session_id": session_id,
        "original_filename": original_filename,
        "sha256": sha256,
        "files": [],
    }

    try:
        shutil.copy2(staging_path, dest / original_filename)

        if staging_path.lower().endswith(".zip"):
            ratio_limit = settings.zip_max_uncompressed_ratio
            single_limit = settings.zip_max_single_file_bytes
            zip_size = os.path.getsize(staging_path)

            with zipfile.ZipFile(staging_path, "r") as zf:
                total_uncompressed = sum(i.file_size for i in zf.infolist())
                if zip_size > 0 and total_uncompressed / zip_size > ratio_limit:
                    shutil.rmtree(dest, ignore_errors=True)
                    return {"ok": False, "errors": ["疑似 Zip Bomb，解压比超限"]}
                for info in zf.infolist():
                    if info.file_size > single_limit:
                        shutil.rmtree(dest, ignore_errors=True)
                        return {"ok": False, "errors": [f"单文件超限: {info.filename}"]}

                zf.extractall(dest / "uploads")

            for root, _, files in os.walk(dest / "uploads"):
                for fname in files:
                    fpath = Path(root) / fname
                    rel = fpath.relative_to(dest)
                    manifest["files"].append({
                        "path": str(rel).replace("\\", "/"),
                        "size": fpath.stat().st_size,
                        "ext": fpath.suffix.lower(),
                    })
        else:
            manifest["files"].append({
                "path": original_filename,
                "size": os.path.getsize(staging_path),
                "ext": Path(original_filename).suffix.lower(),
            })
    except zipfile.BadZipFile:
        shutil.rmtree(dest, ignore_errors=True)
        return {"ok": False, "errors": ["无效的 ZIP 文件"]}
    except Exception as e:
        shutil.rmtree(dest, ignore_errors=True)
        return {"ok": False, "errors": [str(e)]}

    manifest_path = dest / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    _manifests[evidence_id] = manifest
    _evidence_case_map[evidence_id] = case_id

    return {"ok": True, "data": {"evidence_id": evidence_id, "manifest": manifest}}


def get_evidence_manifest(evidence_id: str) -> dict[str, Any] | None:
    """获取证据清单。先查内存缓存，再查磁盘。"""
    if evidence_id in _manifests:
        return _manifests[evidence_id]
    ev_dir = _resolve_evidence_dir(evidence_id)
    if ev_dir:
        manifest_path = ev_dir / "manifest.json"
        if manifest_path.is_file():
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            _manifests[evidence_id] = data
            return data
    return None


def get_evidence_dir(evidence_id: str) -> Path | None:
    """获取证据目录路径。"""
    return _resolve_evidence_dir(evidence_id)


def read_evidence_file(evidence_id: str, inner_path: str, max_bytes: int = 500_000) -> dict[str, Any]:
    """
    读取证据包内指定文件内容。
    inner_path 为 manifest 中的 path，如 uploads/auto/ForensicCollection/result/ioc_summary.csv
    """
    base = _resolve_evidence_dir(evidence_id)
    if not base:
        return {"ok": False, "error": f"证据不存在: {evidence_id}"}
    target = (base / inner_path).resolve()
    if not str(target).startswith(str(base.resolve())):
        return {"ok": False, "error": "路径越界"}
    if not target.is_file():
        return {"ok": False, "error": f"文件不存在: {inner_path}"}
    size = target.stat().st_size
    try:
        content = target.read_bytes()[:max_bytes]
        text = content.decode("utf-8", errors="replace")
        return {"ok": True, "content": text, "size": size, "truncated": size > max_bytes}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def classify_evidence_files(evidence_id: str) -> dict[str, Any]:
    """
    对证据包内文件进行分类：binary（二进制/样本）、log（日志/文本）、other。
    返回 { binary: [file_info], log: [file_info], other: [file_info] }
    """
    manifest = get_evidence_manifest(evidence_id)
    if not manifest:
        return {"binary": [], "log": [], "other": []}
    result: dict[str, list[dict[str, Any]]] = {"binary": [], "log": [], "other": []}
    for f in manifest.get("files", []):
        ext = (f.get("ext") or "").lower()
        path = f.get("path", "")
        info = {"path": path, "size": f.get("size", 0), "ext": ext}
        if ext in BINARY_EXTENSIONS:
            result["binary"].append(info)
        elif ext in LOG_EXTENSIONS:
            result["log"].append(info)
        else:
            result["other"].append(info)
    return result


def session_artifacts_get(session_id: str, artifact_id: str) -> dict[str, Any]:
    """获取会话 artifact。"""
    key = f"{session_id}:{artifact_id}"
    data = _artifacts.get(key)
    if data:
        return {"ok": True, "data": data}
    return {"ok": False, "errors": ["artifact 不存在"]}


def session_artifacts_put(session_id: str, artifact_id: str, data: dict[str, Any]) -> None:
    """存储会话 artifact。"""
    key = f"{session_id}:{artifact_id}"
    _artifacts[key] = data


def _sanitize_path(path: str) -> str:
    """路径安全校验：禁止 .. 等路径遍历。"""
    p = path.replace("\\", "/").strip("/")
    if ".." in p or p.startswith("/"):
        raise ValueError("非法路径")
    return p


def evidence_ls(evidence_id: str, path_prefix: str = "") -> dict[str, Any]:
    """
    列出证据包内文件，支持路径前缀过滤。
    返回 { ok, files: [{path, size, ext}, ...] } 或 { ok: false, error }
    """
    manifest = get_evidence_manifest(evidence_id)
    if not manifest:
        return {"ok": False, "error": f"证据不存在: {evidence_id}"}
    prefix = _sanitize_path(path_prefix) if path_prefix else ""
    files = []
    for f in manifest.get("files", []):
        p = f.get("path", "")
        if prefix and not p.startswith(prefix):
            continue
        files.append({"path": p, "size": f.get("size", 0), "ext": f.get("ext", "")})
    return {"ok": True, "files": files}


def evidence_read(
    evidence_id: str,
    inner_path: str,
    offset: int = 0,
    limit: int = 100,
    max_bytes: int = 100_000,
) -> dict[str, Any]:
    """
    分段读取证据文件（按行），支持大文件。
    offset: 起始行号（0-based）
    limit: 读取行数
    """
    result = read_evidence_file(evidence_id, _sanitize_path(inner_path), max_bytes=max_bytes)
    if not result.get("ok"):
        return result
    content = result["content"]
    lines = content.splitlines()
    total = len(lines)
    start = max(0, offset)
    end = min(total, start + limit)
    selected = lines[start:end]
    return {
        "ok": True,
        "content": "\n".join(selected),
        "total_lines": total,
        "offset": start,
        "limit": limit,
        "size": result.get("size", 0),
        "truncated": result.get("truncated", False),
    }


def evidence_grep(
    evidence_id: str,
    pattern: str,
    path_filter: str = "",
    max_matches: int = 100,
) -> dict[str, Any]:
    """
    在证据包内的文本文件中搜索关键字（字面匹配，非正则）。
    返回匹配行及所在文件。
    """
    manifest = get_evidence_manifest(evidence_id)
    if not manifest:
        return {"ok": False, "error": f"证据不存在: {evidence_id}"}
    prefix = _sanitize_path(path_filter) if path_filter else ""
    matches = []
    for f in manifest.get("files", []):
        p = f.get("path", "")
        if prefix and not p.startswith(prefix):
            continue
        ext = (f.get("ext") or "").lower()
        if ext not in LOG_EXTENSIONS and ext not in {".txt", ".log", ".csv", ".json", ".jsonl"}:
            continue
        r = read_evidence_file(evidence_id, p, max_bytes=500_000)
        if not r.get("ok"):
            continue
        for i, line in enumerate(r["content"].splitlines()):
            if pattern in line:
                matches.append({"file": p, "line_num": i + 1, "content": line[:500]})
                if len(matches) >= max_matches:
                    return {"ok": True, "matches": matches, "truncated": True}
    return {"ok": True, "matches": matches, "truncated": False}


def evidence_glob(evidence_id: str, pattern: str) -> dict[str, Any]:
    """
    按 glob 模式匹配证据包内文件名。
    pattern 支持 * 通配，如 "*.log", "uploads/**/*.csv"
    """
    import fnmatch
    manifest = get_evidence_manifest(evidence_id)
    if not manifest:
        return {"ok": False, "error": f"证据不存在: {evidence_id}"}
    matched = []
    for f in manifest.get("files", []):
        p = f.get("path", "")
        if fnmatch.fnmatch(p, pattern):
            matched.append({"path": p, "size": f.get("size", 0), "ext": f.get("ext", "")})
    return {"ok": True, "files": matched}


def workspace_path(case_id: str, session_id: str, rel_path: str) -> Path:
    """
    解析工作区文件路径。
    结构: workspace/{case_id}/sessions/{session_id}/{rel_path}
    确保路径在 session 作用域内，禁止路径遍历。
    case_id 为空时使用 _unknown 占位，保证路径有效。
    """
    settings = get_settings()
    cid = case_id.strip() or "_unknown"
    base = settings.workspace_root_dir() / cid / "sessions" / session_id
    safe = _sanitize_path(rel_path)
    full = (base / safe).resolve()
    base_resolved = base.resolve()
    if not str(full).startswith(str(base_resolved)):
        raise ValueError("路径越界")
    return full


def workspace_write(case_id: str, session_id: str, rel_path: str, content: str) -> dict[str, Any]:
    """写入工作区文件（分析笔记、中间结果等）。"""
    try:
        p = workspace_path(case_id, session_id, rel_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return {"ok": True, "path": rel_path}
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def workspace_list_files(case_id: str, session_id: str) -> dict[str, Any]:
    """
    列出会话工作区内的所有文件（递归）。
    返回 { ok, files: [{path, size, is_dir}, ...] }
    """
    settings = get_settings()
    cid = (case_id or "").strip() or "_unknown"
    base = settings.workspace_root_dir() / cid / "sessions" / session_id
    if not base.is_dir():
        return {"ok": True, "files": []}
    files = []
    for p in base.rglob("*"):
        if p.is_file():
            rel = str(p.relative_to(base)).replace("\\", "/")
            files.append({"path": rel, "size": p.stat().st_size, "is_dir": False})
    return {"ok": True, "files": sorted(files, key=lambda x: x["path"])}


def workspace_read(case_id: str, session_id: str, rel_path: str, max_bytes: int = 500_000) -> dict[str, Any]:
    """读取工作区文件。支持 conversation_history.md, tool_results/* 等。"""
    try:
        p = workspace_path(case_id, session_id, rel_path)
        if not p.is_file():
            return {"ok": False, "error": f"文件不存在: {rel_path}"}
        content = p.read_bytes()[:max_bytes]
        text = content.decode("utf-8", errors="replace")
        return {
            "ok": True,
            "content": text,
            "size": p.stat().st_size,
            "truncated": p.stat().st_size > max_bytes,
        }
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def delete_evidence_for_case(case_id: str) -> None:
    """删除案件关联的全部证据（磁盘 + 内存）。"""
    settings = get_settings()
    evidence_dir = settings.evidence_storage_dir()
    to_delete = [eid for eid, cid in _evidence_case_map.items() if cid == case_id]
    for eid in to_delete:
        _manifests.pop(eid, None)
        _evidence_case_map.pop(eid, None)
    case_dir = evidence_dir / case_id
    if case_dir.is_dir():
        shutil.rmtree(case_dir, ignore_errors=True)
