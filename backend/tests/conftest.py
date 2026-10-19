"""
Neo 测试公共 fixture。
所有集成测试共享：FastAPI TestClient、鉴权 token、临时证据目录等。
AUTH_DISABLED=true 使集成测试跳过 JWT 校验。
"""
import os
import shutil
import zipfile
from io import BytesIO
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("AUTH_DISABLED", "true")
os.environ.setdefault("DATABASE_URL", "")


@pytest.fixture(scope="session")
def app():
    """创建 FastAPI 应用实例（session 级复用）。"""
    from src.api.app import create_app
    from src.core.auth import _init_default_users

    application = create_app()
    _init_default_users()
    return application


@pytest.fixture()
def client(app):
    """每个测试函数获得独立的 TestClient。"""
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture()
def admin_headers():
    """跳过鉴权时无需 token，返回空 header；可按需扩展为真实 JWT。"""
    return {}


@pytest.fixture()
def tmp_evidence_dir(tmp_path: Path):
    """
    为每个测试提供隔离的证据存储目录。
    通过 monkeypatch 覆盖 Settings 中的路径。
    """
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    staging_dir = tmp_path / "staging"
    staging_dir.mkdir()

    original_get_settings = None
    try:
        from src.core.config import get_settings as _orig
        original_get_settings = _orig

        class _PatchedSettings:
            """代理 Settings，仅覆盖存储路径。"""
            def __init__(self):
                self._inner = original_get_settings()

            def __getattr__(self, name):
                return getattr(self._inner, name)

            def evidence_storage_dir(self):
                return evidence_dir

            def evidence_staging_dir(self):
                return staging_dir

        _factory = lambda: _PatchedSettings()

        import src.core.config as config_mod
        import src.tools.evidence.tools as tools_mod
        config_mod.get_settings = _factory
        tools_mod.get_settings = _factory
        yield {"evidence": evidence_dir, "staging": staging_dir, "root": tmp_path}
    finally:
        if original_get_settings:
            import src.core.config as config_mod
            import src.tools.evidence.tools as tools_mod
            config_mod.get_settings = original_get_settings
            tools_mod.get_settings = original_get_settings


@pytest.fixture()
def sample_zip(tmp_path: Path) -> Path:
    """生成一个包含混合文件类型的测试 ZIP 证据包。"""
    zip_path = tmp_path / "test_evidence.zip"
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("logs/ioc_summary.csv", "ioc_type,ioc_value,md5_hash\nip,192.168.1.100,\ndomain,evil.example.com,\n")
        zf.writestr("logs/events.json", '{"event": "login_failed", "user": "admin", "ip": "10.0.0.1"}')
        zf.writestr("logs/syslog.txt", "Feb 27 10:00:00 host sshd[1234]: Failed password for root from 192.168.1.50\n")
        zf.writestr("samples/malware.exe", b"\x4d\x5a" + b"\x00" * 100)
        zf.writestr("samples/dropper.dll", b"\x4d\x5a" + b"\x00" * 50)
        zf.writestr("misc/readme.md", "# Evidence Package\nCollected 2026-02-27")
        zf.writestr("misc/config.yaml", "setting: value\n")
    zip_path.write_bytes(buf.getvalue())
    return zip_path


@pytest.fixture()
def created_case(client, admin_headers) -> dict:
    """创建一个案件并返回其信息。"""
    resp = client.post("/api/v1/projects/proj1/cases", json={"name": "测试案件"}, headers=admin_headers)
    assert resp.status_code == 200
    return resp.json()


@pytest.fixture()
def created_session(client, admin_headers, created_case) -> dict:
    """创建案件后创建一个会话。"""
    case_id = created_case["id"]
    resp = client.post(f"/api/v1/cases/{case_id}/sessions", headers=admin_headers)
    assert resp.status_code == 200
    return resp.json()
