"""
将证据包内逻辑路径（manifest 中的 path）解析为磁盘绝对路径。
"""
from __future__ import annotations

import logging
from pathlib import Path, PurePosixPath

from src.core.config import get_settings
from src.services.session_store import get_session
from src.tools.evidence.tools import get_evidence_dir, get_evidence_manifest

logger = logging.getLogger(__name__)


def _norm_inner(p: str) -> str:
    s = (p or "").replace("\\", "/").strip()
    while s.startswith("/"):
        s = s[1:]
    return s


def _list_evidence_ids_for_case(case_id: str) -> list[str]:
    cid = (case_id or "").strip()
    if not cid:
        return []
    base = get_settings().evidence_storage_dir() / cid
    if not base.is_dir():
        return []
    out: list[str] = []
    for d in base.iterdir():
        if d.is_dir() and (d / "manifest.json").is_file():
            out.append(d.name)
    return sorted(out)


def resolve_sample_path(case_id: str, session_id: str, sample_path: str) -> tuple[str, Path, str] | None:
    """
    在会话关联的证据包（若无则退化为整个案件的证据目录）中查找 sample_path。

    Returns:
        (evidence_id, absolute_path, manifest_inner_path) 或 None
    """
    want = _norm_inner(sample_path)
    if not want:
        return None

    sess = get_session((session_id or "").strip()) if session_id else None
    eids: list[str] = []
    if sess and sess.get("evidence_ids"):
        eids = list(sess["evidence_ids"])
    if not eids:
        eids = _list_evidence_ids_for_case(case_id)

    def try_resolve(eid: str, mp: str) -> Path | None:
        base = get_evidence_dir(eid)
        if not base:
            return None
        target = (base / PurePosixPath(mp)).resolve()
        if not str(target).startswith(str(base.resolve())):
            return None
        return target if target.is_file() else None

    # 1) 精确匹配 manifest path
    for eid in eids:
        manifest = get_evidence_manifest(eid)
        if not manifest:
            continue
        for f in manifest.get("files", []):
            mp = _norm_inner(str(f.get("path", "")))
            if mp == want:
                t = try_resolve(eid, mp)
                if t:
                    return eid, t, mp

    # 2) 后缀匹配（用户只传子路径 uploads/x.exe）
    for eid in eids:
        manifest = get_evidence_manifest(eid)
        if not manifest:
            continue
        for f in manifest.get("files", []):
            mp = _norm_inner(str(f.get("path", "")))
            if mp.endswith("/" + want):
                t = try_resolve(eid, mp)
                if t:
                    return eid, t, mp

    # 3) 按文件名唯一匹配
    basename = want.split("/")[-1]
    hits: list[tuple[str, Path, str]] = []
    for eid in eids:
        manifest = get_evidence_manifest(eid)
        if not manifest:
            continue
        for f in manifest.get("files", []):
            mp = _norm_inner(str(f.get("path", "")))
            if PurePosixPath(mp).name != basename:
                continue
            t = try_resolve(eid, mp)
            if t:
                hits.append((eid, t, mp))

    if len(hits) == 1:
        return hits[0]
    if len(hits) > 1:
        logger.warning("样本路径 %s 对应多个文件，请使用证据清单中的完整 path", sample_path)

    return None
