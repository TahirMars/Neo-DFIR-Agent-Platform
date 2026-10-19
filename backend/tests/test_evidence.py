"""证据上传、列表与访问控制测试。"""
import io
import zipfile
from pathlib import Path

import pytest


def _make_zip_bytes(files: dict[str, bytes | str]) -> bytes:
    """快速构建 ZIP 字节流。"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            data = content.encode("utf-8") if isinstance(content, str) else content
            zf.writestr(name, data)
    return buf.getvalue()


class TestEvidenceUpload:
    def test_upload_zip(self, client, admin_headers, created_session, tmp_evidence_dir):
        sid = created_session["id"]
        zip_bytes = _make_zip_bytes({"logs/test.csv": "col1,col2\na,b\n", "samples/bad.exe": b"\x4d\x5a\x00"})
        resp = client.post(
            f"/api/v1/sessions/{sid}/evidence/upload",
            files={"file": ("evidence.zip", zip_bytes, "application/zip")},
            headers=admin_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["evidence_id"].startswith("ev-")
        assert data["session_id"] == sid
        assert "manifest" in data
        assert len(data["manifest"]["files"]) == 2

    def test_upload_non_zip_rejected(self, client, admin_headers, created_session):
        sid = created_session["id"]
        resp = client.post(
            f"/api/v1/sessions/{sid}/evidence/upload",
            files={"file": ("data.txt", b"hello", "text/plain")},
            headers=admin_headers,
        )
        assert resp.status_code == 400

    def test_upload_nonexistent_session(self, client, admin_headers):
        zip_bytes = _make_zip_bytes({"a.csv": "x"})
        resp = client.post(
            "/api/v1/sessions/session-000000000000/evidence/upload",
            files={"file": ("e.zip", zip_bytes, "application/zip")},
            headers=admin_headers,
        )
        assert resp.status_code == 404


class TestEvidenceList:
    def test_list_evidence(self, client, admin_headers, created_session, tmp_evidence_dir):
        sid = created_session["id"]
        zip_bytes = _make_zip_bytes({"log.txt": "test log"})
        client.post(
            f"/api/v1/sessions/{sid}/evidence/upload",
            files={"file": ("e.zip", zip_bytes, "application/zip")},
            headers=admin_headers,
        )
        resp = client.get(f"/api/v1/sessions/{sid}/evidence", headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        assert data["items"][0]["evidence_id"]

    def test_list_evidence_empty_session(self, client, admin_headers, created_session):
        sid = created_session["id"]
        resp = client.get(f"/api/v1/sessions/{sid}/evidence", headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json()["total"] == 0

    def test_list_evidence_nonexistent_session(self, client, admin_headers):
        resp = client.get("/api/v1/sessions/session-000000000000/evidence", headers=admin_headers)
        assert resp.status_code == 404
