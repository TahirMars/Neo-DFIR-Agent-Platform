"""ID 生成与校验测试。"""
import pytest

from src.core.ids import (
    PREFIX_CASE, PREFIX_SESSION, PREFIX_EVIDENCE, PREFIX_REPORT, PREFIX_MESSAGE,
    generate_id, is_valid_id,
    new_case_id, new_session_id, new_evidence_id, new_report_id, new_message_id,
)


class TestIdGeneration:
    def test_case_id_format(self):
        cid = new_case_id()
        assert cid.startswith("case-")
        assert len(cid) == len("case-") + 12
        assert is_valid_id(cid, PREFIX_CASE)

    def test_session_id_format(self):
        sid = new_session_id()
        assert sid.startswith("session-")
        assert len(sid) == len("session-") + 12
        assert is_valid_id(sid, PREFIX_SESSION)

    def test_evidence_id_format(self):
        eid = new_evidence_id()
        assert eid.startswith("ev-")
        assert len(eid) == len("ev-") + 12
        assert is_valid_id(eid, PREFIX_EVIDENCE)

    def test_report_id_format(self):
        rid = new_report_id()
        assert rid.startswith("report-")
        assert len(rid) == len("report-") + 12
        assert is_valid_id(rid, PREFIX_REPORT)

    def test_message_id_format(self):
        mid = new_message_id()
        assert mid.startswith("msg-")
        assert len(mid) == len("msg-") + 12
        assert is_valid_id(mid, PREFIX_MESSAGE)

    def test_uniqueness(self):
        ids = {new_case_id() for _ in range(100)}
        assert len(ids) == 100

    def test_generate_id_custom_prefix(self):
        cid = generate_id("custom")
        assert cid.startswith("custom-")
        assert is_valid_id(cid)


class TestIdValidation:
    def test_valid_ids(self):
        assert is_valid_id("case-93d4e4c82dec", PREFIX_CASE)
        assert is_valid_id("session-453e082cff8a", PREFIX_SESSION)
        assert is_valid_id("ev-52598b8403a8", PREFIX_EVIDENCE)
        assert is_valid_id("report-7f3a1b2c4d5e", PREFIX_REPORT)
        assert is_valid_id("msg-a1b2c3d4e5f6", PREFIX_MESSAGE)

    def test_wrong_prefix(self):
        assert not is_valid_id("session-453e082cff8a", PREFIX_CASE)
        assert not is_valid_id("case-93d4e4c82dec", PREFIX_SESSION)
        assert not is_valid_id("case-93d4e4c82dec", PREFIX_EVIDENCE)

    def test_invalid_format(self):
        assert not is_valid_id("")
        assert not is_valid_id("case-ghost")
        assert not is_valid_id("case-ABCDEF123456")  # uppercase
        assert not is_valid_id("case-123")  # too short
        assert not is_valid_id("case-93d4e4c82dec0")  # too long
        assert not is_valid_id("93d4e4c82dec")  # no prefix
        assert not is_valid_id("CASE-93d4e4c82dec")  # uppercase prefix

    def test_generic_validation(self):
        assert is_valid_id("case-93d4e4c82dec")
        assert is_valid_id("ev-52598b8403a8")
        assert not is_valid_id("bad")
        assert not is_valid_id("")


class TestIdValidationInApi:
    """集成测试：API 层拒绝格式错误的 ID。"""

    def test_reject_malformed_case_id(self, client, admin_headers):
        resp = client.get("/api/v1/cases/bad-id", headers=admin_headers)
        assert resp.status_code == 400

    def test_reject_malformed_session_id(self, client, admin_headers):
        resp = client.get("/api/v1/sessions/bad-id", headers=admin_headers)
        assert resp.status_code == 400

    def test_reject_malformed_session_id_in_reports(self, client, admin_headers):
        resp = client.get("/api/v1/sessions/nope/reports", headers=admin_headers)
        assert resp.status_code == 400

    def test_accept_valid_format_case_id(self, client, admin_headers):
        resp = client.get("/api/v1/cases/case-000000000000", headers=admin_headers)
        assert resp.status_code == 404

    def test_accept_valid_format_session_id(self, client, admin_headers):
        resp = client.get("/api/v1/sessions/session-000000000000", headers=admin_headers)
        assert resp.status_code == 404
