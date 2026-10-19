"""
本地静态特征提取（不依赖 malware-static MCP）：哈希、熵、字符串、简易 PE 头。
可选：环境已安装 python-magic 时补充 MIME。
"""
from __future__ import annotations

import hashlib
import math
import re
import struct
from pathlib import Path
from typing import Any


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    ent = 0.0
    ln = len(data)
    for c in counts:
        if c == 0:
            continue
        p = c / ln
        ent -= p * math.log2(p)
    return round(ent, 4)


def _file_hashes(path: Path) -> dict[str, str]:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def _extract_ascii_strings(data: bytes, min_len: int = 5, max_strings: int = 200) -> list[str]:
    pat = re.compile(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}")
    out: list[str] = []
    for m in pat.finditer(data):
        if len(out) >= max_strings:
            break
        try:
            out.append(m.group().decode("ascii"))
        except Exception:
            continue
    return out


def _pe_quick(path: Path) -> dict[str, Any] | None:
    try:
        with open(path, "rb") as f:
            hdr = f.read(0x40)
            if len(hdr) < 0x40 or hdr[:2] != b"MZ":
                return None
            e_lfanew = struct.unpack_from("<I", hdr, 0x3C)[0]
            f.seek(e_lfanew)
            if f.read(4) != b"PE\x00\x00":
                return None
            coff = f.read(20)
            if len(coff) < 20:
                return None
            machine, num_sections, _, _, _, _, size_opt, characteristics = struct.unpack("<HHIIIHH", coff)
            is_dll = bool(characteristics & 0x2000)
            opt = f.read(size_opt)
            if len(opt) < 0x46:
                return {
                    "format": "pe",
                    "machine": machine,
                    "num_sections": num_sections,
                    "is_dll": is_dll,
                    "subsystem": None,
                    "pe_type": "unknown",
                }
            magic_opt = struct.unpack_from("<H", opt, 0)[0]
            pe_type = "PE32+" if magic_opt == 0x20B else "PE32" if magic_opt == 0x10B else f"unknown(0x{magic_opt:x})"
            subsystem = struct.unpack_from("<H", opt, 0x44)[0]
            entry_rva = struct.unpack_from("<I", opt, 0x10)[0]
            return {
                "format": "pe",
                "machine": machine,
                "machine_name": {0x14C: "I386", 0x8664: "AMD64", 0xAA64: "ARM64"}.get(machine, f"0x{machine:x}"),
                "num_sections": num_sections,
                "is_dll": is_dll,
                "subsystem": subsystem,
                "pe_type": pe_type,
                "address_of_entrypoint_rva": entry_rva,
            }
    except (OSError, struct.error, ValueError):
        return None


def _magic_mime(path: Path) -> str | None:
    try:
        import magic  # type: ignore[import-untyped]

        m = magic.Magic(mime=True)
        return m.from_file(str(path))
    except Exception:
        return None


def build_static_report(
    path: Path,
    *,
    evidence_id: str,
    inner_path: str,
    strings_max_bytes: int = 2 * 1024 * 1024,
) -> dict[str, Any]:
    size = path.stat().st_size
    hashes = _file_hashes(path)

    with open(path, "rb") as f:
        ent_chunk = f.read(256 * 1024)
        f.seek(0)
        str_chunk = f.read(strings_max_bytes)

    strings_preview = _extract_ascii_strings(str_chunk)
    entropy = _shannon_entropy(ent_chunk)

    pe = _pe_quick(path)
    mime = _magic_mime(path)

    file_type = "unknown"
    if pe:
        file_type = "pe"
    elif mime:
        file_type = mime
    else:
        file_type = path.suffix.lower().lstrip(".") or "unknown"

    return {
        "sample_ref": inner_path,
        "evidence_id": evidence_id,
        "size_bytes": size,
        "file_type": file_type,
        "mime": mime,
        "hashes": hashes,
        "entropy_sample": entropy,
        "pe": pe,
        "strings_preview": strings_preview,
        "yara_hits": [],
        "notes": "本地引擎：字符串取自文件前 %d 字节；YARA 未启用。完整 MCP 见 ref/sample_analysis/malware-static。" % len(str_chunk),
    }
