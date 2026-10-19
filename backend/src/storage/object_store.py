"""
证据区与暂存区访问封装；仅由 mcp/evidence 使用。
路径规范化、Zip Bomb 防护。
"""
import hashlib
import zipfile
from pathlib import Path
from typing import Any

from src.core.config import get_settings


def normalize_inner_path(inner_path: str) -> str:
    """
    规范化证据包内路径：拒绝 ..、绝对路径、前导斜杠。
    返回规范化的相对路径，若非法则抛出 ValueError。
    """
    if not inner_path or inner_path.strip() != inner_path:
        raise ValueError("路径不能为空或含首尾空白")
    p = Path(inner_path.replace("\\", "/").lstrip("/"))
    try:
        p = p.resolve()
    except Exception:
        pass
    parts = p.parts
    if ".." in parts or (parts and parts[0] == "/"):
        raise ValueError("禁止路径穿越或绝对路径")
    return str(p).replace("\\", "/")


def safe_zip_list(zip_path: Path) -> list[dict[str, Any]]:
    """
    安全列出 ZIP 内条目；检查解压比与单文件大小，防 Zip Bomb。
    返回 [{"path": str, "size": int, "compressed": int}, ...]
    """
    settings = get_settings()
    entries: list[dict[str, Any]] = []
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            path = normalize_inner_path(info.filename)
            if info.is_dir():
                entries.append({"path": path + "/", "size": 0, "compressed": 0})
                continue
            uncompressed = info.file_size
            compressed = info.compress_size
            if compressed > 0 and uncompressed > compressed * settings.zip_max_uncompressed_ratio:
                raise ValueError(f"解压比过大（Zip Bomb 防护）: {path}")
            if uncompressed > settings.zip_max_single_file_bytes:
                raise ValueError(f"单文件过大: {path}")
            entries.append({"path": path, "size": uncompressed, "compressed": compressed})
    return entries


def zip_read_entry(zip_path: Path, inner_path: str, max_bytes: int | None = None) -> bytes:
    """从 ZIP 中读取单个条目；限制最大字节数。"""
    inner_path = normalize_inner_path(inner_path)
    settings = get_settings()
    with zipfile.ZipFile(zip_path, "r") as zf:
        try:
            info = zf.getinfo(inner_path)
        except KeyError:
            try:
                info = zf.getinfo(inner_path + "/")
            except KeyError:
                raise FileNotFoundError(f"ZIP 内不存在: {inner_path}")
        if info.is_dir():
            raise IsADirectoryError(inner_path)
        if info.file_size > settings.zip_max_single_file_bytes:
            raise ValueError("单文件过大")
        limit = min(info.file_size, max_bytes or settings.zip_max_single_file_bytes)
        with zf.open(info) as f:
            return f.read(limit)


def zip_get_stat(zip_path: Path, inner_path: str) -> dict[str, Any]:
    """ZIP 内条目 stat：size, mtime_utc；sha256 需按需计算。"""
    inner_path = normalize_inner_path(inner_path)
    with zipfile.ZipFile(zip_path, "r") as zf:
        try:
            info = zf.getinfo(inner_path)
        except KeyError:
            raise FileNotFoundError(f"ZIP 内不存在: {inner_path}")
        return {
            "size": info.file_size,
            "mtime_utc": info.date_time,
            "sha256": None,
        }


def compute_sha256(path: Path, max_bytes: int | None = None) -> str:
    """计算文件或 ZIP 内首字节的 SHA256（可选限制字节数）。"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        read = 0
        limit = max_bytes or (2 * 1024 * 1024)
        while chunk := f.read(65536):
            h.update(chunk)
            read += len(chunk)
            if read >= limit:
                break
    return h.hexdigest()
