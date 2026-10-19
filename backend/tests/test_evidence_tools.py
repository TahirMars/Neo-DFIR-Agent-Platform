"""证据工具单元测试：ingest、manifest、分类、读取、artifact。"""
import io
import json
import zipfile
from pathlib import Path

import pytest


def _make_zip(dest: Path, files: dict[str, bytes | str]) -> Path:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            data = content.encode("utf-8") if isinstance(content, str) else content
            zf.writestr(name, data)
    dest.write_bytes(buf.getvalue())
    return dest


class TestEvidenceIngest:
    def test_ingest_zip(self, tmp_evidence_dir):
        from src.tools.evidence.tools import evidence_ingest, get_evidence_manifest
        staging = tmp_evidence_dir["staging"]
        zip_path = _make_zip(staging / "test.zip", {"logs/a.csv": "x,y\n1,2\n", "samples/b.exe": b"\x4d\x5a\x00"})

        result = evidence_ingest("case1", "sess1", str(zip_path))
        assert result["ok"] is True
        eid = result["data"]["evidence_id"]
        assert eid.startswith("ev-")

        manifest = result["data"]["manifest"]
        assert manifest["case_id"] == "case1"
        assert manifest["sha256"]
        assert len(manifest["files"]) == 2

        ev_dir = tmp_evidence_dir["evidence"] / "case1" / eid
        assert ev_dir.is_dir()
        assert (ev_dir / "evidence.zip").is_file()
        assert (ev_dir / "manifest.json").is_file()

        disk_manifest = get_evidence_manifest(eid)
        assert disk_manifest is not None
        assert disk_manifest["evidence_id"] == eid

    def test_ingest_nonexistent_file(self, tmp_evidence_dir):
        from src.tools.evidence.tools import evidence_ingest
        result = evidence_ingest("c1", "s1", "/nonexistent/path.zip")
        assert result["ok"] is False
        assert "不存在" in result["errors"][0]

    def test_ingest_bad_zip(self, tmp_evidence_dir):
        from src.tools.evidence.tools import evidence_ingest
        bad = tmp_evidence_dir["staging"] / "bad.zip"
        bad.write_bytes(b"this is not a zip")
        result = evidence_ingest("c1", "s1", str(bad))
        assert result["ok"] is False
        assert not any((tmp_evidence_dir["evidence"] / "c1").iterdir()) if (tmp_evidence_dir["evidence"] / "c1").exists() else True

    def test_ingest_preserves_original_filename(self, tmp_evidence_dir):
        from src.tools.evidence.tools import evidence_ingest
        staging = tmp_evidence_dir["staging"]
        zip_path = _make_zip(staging / "my_evidence_2026.zip", {"note.txt": "hello"})
        result = evidence_ingest("case-x", "s1", str(zip_path), original_filename="my_evidence_2026.zip")
        assert result["ok"] is True
        eid = result["data"]["evidence_id"]
        stored_zip = tmp_evidence_dir["evidence"] / "case-x" / eid / "my_evidence_2026.zip"
        assert stored_zip.is_file()

    def test_same_case_shares_directory(self, tmp_evidence_dir):
        from src.tools.evidence.tools import evidence_ingest
        staging = tmp_evidence_dir["staging"]
        z1 = _make_zip(staging / "a.zip", {"a.txt": "aaa"})
        z2 = _make_zip(staging / "b.zip", {"b.txt": "bbb"})
        r1 = evidence_ingest("case-shared", "s1", str(z1))
        r2 = evidence_ingest("case-shared", "s2", str(z2))
        assert r1["ok"] and r2["ok"]
        case_dir = tmp_evidence_dir["evidence"] / "case-shared"
        ev_dirs = [d for d in case_dir.iterdir() if d.is_dir()]
        assert len(ev_dirs) == 2


class TestClassifyEvidence:
    def test_classify_mixed(self, tmp_evidence_dir):
        from src.tools.evidence.tools import evidence_ingest, classify_evidence_files
        staging = tmp_evidence_dir["staging"]
        zip_path = _make_zip(staging / "mixed.zip", {
            "logs/ioc.csv": "ioc_type,value\nip,1.2.3.4\n",
            "logs/events.json": '{"event":"test"}',
            "logs/access.log": "GET /index.html 200\n",
            "samples/malware.exe": b"\x4d\x5a" + b"\x00" * 50,
            "samples/lib.dll": b"\x4d\x5a" + b"\x00" * 30,
            "samples/installer.msi": b"\xd0\xcf",
            "other/photo.png": b"\x89PNG",
            "other/unknown.xyz": b"\x00\x01",
        })
        result = evidence_ingest("c1", "s1", str(zip_path))
        eid = result["data"]["evidence_id"]

        classified = classify_evidence_files(eid)
        assert len(classified["log"]) == 3
        assert len(classified["binary"]) == 3
        assert len(classified["other"]) == 2

    def test_classify_log_extensions(self, tmp_evidence_dir):
        from src.tools.evidence.tools import evidence_ingest, classify_evidence_files
        staging = tmp_evidence_dir["staging"]
        zip_path = _make_zip(staging / "logs.zip", {
            "a.csv": "x", "b.json": "{}", "c.jsonl": "{}\n",
            "d.log": "line", "e.txt": "text", "f.xml": "<x/>",
            "g.html": "<h1>", "h.yaml": "k: v", "i.ini": "[s]",
        })
        result = evidence_ingest("c1", "s1", str(zip_path))
        classified = classify_evidence_files(result["data"]["evidence_id"])
        assert len(classified["log"]) == 9
        assert len(classified["binary"]) == 0

    def test_classify_nonexistent_evidence(self):
        from src.tools.evidence.tools import classify_evidence_files
        classified = classify_evidence_files("nonexistent-id")
        assert classified == {"binary": [], "log": [], "other": []}


class TestReadEvidenceFile:
    def test_read_text_file(self, tmp_evidence_dir):
        from src.tools.evidence.tools import evidence_ingest, read_evidence_file
        staging = tmp_evidence_dir["staging"]
        csv_content = "ioc_type,ioc_value\nip,10.0.0.1\ndomain,evil.com\n"
        zip_path = _make_zip(staging / "r.zip", {"data/ioc.csv": csv_content})
        result = evidence_ingest("c1", "s1", str(zip_path))
        eid = result["data"]["evidence_id"]

        read_result = read_evidence_file(eid, "uploads/data/ioc.csv")
        assert read_result["ok"] is True
        assert "ioc_type" in read_result["content"]
        assert read_result["truncated"] is False

    def test_read_path_traversal_blocked(self, tmp_evidence_dir):
        from src.tools.evidence.tools import evidence_ingest, read_evidence_file
        staging = tmp_evidence_dir["staging"]
        zip_path = _make_zip(staging / "safe.zip", {"a.txt": "content"})
        result = evidence_ingest("c1", "s1", str(zip_path))
        eid = result["data"]["evidence_id"]

        read_result = read_evidence_file(eid, "../../etc/passwd")
        assert read_result["ok"] is False

    def test_read_nonexistent_inner_path(self, tmp_evidence_dir):
        from src.tools.evidence.tools import evidence_ingest, read_evidence_file
        staging = tmp_evidence_dir["staging"]
        zip_path = _make_zip(staging / "x.zip", {"a.txt": "ok"})
        result = evidence_ingest("c1", "s1", str(zip_path))
        eid = result["data"]["evidence_id"]

        read_result = read_evidence_file(eid, "uploads/nonexistent.txt")
        assert read_result["ok"] is False


class TestSessionArtifacts:
    def test_put_and_get(self):
        from src.tools.evidence.tools import session_artifacts_put, session_artifacts_get
        session_artifacts_put("s1", "a1", {"json": {"markdown": "# Report"}})
        result = session_artifacts_get("s1", "a1")
        assert result["ok"] is True
        assert result["data"]["json"]["markdown"] == "# Report"

    def test_get_nonexistent(self):
        from src.tools.evidence.tools import session_artifacts_get
        result = session_artifacts_get("s999", "a999")
        assert result["ok"] is False


class TestSessionCreate:
    def test_create_session_via_mcp(self, client, admin_headers, created_case):
        from src.tools.evidence.tools import session_create
        result = session_create({"case_id": created_case["id"]})
        assert result["ok"] is True
        assert result["data"]["session_id"].startswith("session-")

    def test_create_session_empty_case(self):
        from src.tools.evidence.tools import session_create
        result = session_create({"case_id": ""})
        assert result["ok"] is False

    def test_create_session_invalid_case(self):
        from src.tools.evidence.tools import session_create
        result = session_create({"case_id": "case-nonexistent"})
        assert result["ok"] is False


class TestDeleteEvidence:
    def test_delete_for_case(self, tmp_evidence_dir):
        from src.tools.evidence.tools import evidence_ingest, delete_evidence_for_case, get_evidence_manifest
        staging = tmp_evidence_dir["staging"]
        zip_path = _make_zip(staging / "d.zip", {"a.txt": "data"})
        result = evidence_ingest("case-del", "s1", str(zip_path))
        eid = result["data"]["evidence_id"]
        assert get_evidence_manifest(eid) is not None

        case_dir = tmp_evidence_dir["evidence"] / "case-del"
        assert case_dir.is_dir()

        delete_evidence_for_case("case-del")
        assert not case_dir.exists()

    def test_delete_multiple_evidence_in_case(self, tmp_evidence_dir):
        from src.tools.evidence.tools import evidence_ingest, delete_evidence_for_case
        staging = tmp_evidence_dir["staging"]
        _make_zip(staging / "e1.zip", {"a.txt": "1"})
        _make_zip(staging / "e2.zip", {"b.txt": "2"})
        evidence_ingest("case-multi", "s1", str(staging / "e1.zip"))
        evidence_ingest("case-multi", "s2", str(staging / "e2.zip"))

        case_dir = tmp_evidence_dir["evidence"] / "case-multi"
        assert len(list(case_dir.iterdir())) == 2

        delete_evidence_for_case("case-multi")
        assert not case_dir.exists()
