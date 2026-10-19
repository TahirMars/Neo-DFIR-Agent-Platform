"""会话 CRUD、消息与状态测试。"""
import pytest


class TestSessionCreate:
    def test_create_session(self, client, admin_headers, created_case):
        case_id = created_case["id"]
        resp = client.post(f"/api/v1/cases/{case_id}/sessions", headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "id" in data
        assert data["case_id"] == case_id
        assert data["status"] == "pending"

    def test_create_session_nonexistent_case(self, client, admin_headers):
        resp = client.post("/api/v1/cases/case-000000000000/sessions", headers=admin_headers)
        assert resp.status_code == 404


class TestSessionList:
    def test_list_sessions(self, client, admin_headers, created_case):
        case_id = created_case["id"]
        client.post(f"/api/v1/cases/{case_id}/sessions", headers=admin_headers)
        resp = client.get(f"/api/v1/cases/{case_id}/sessions", headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        assert all(s["case_id"] == case_id for s in data["items"])


class TestSessionGet:
    def test_get_session(self, client, admin_headers, created_session):
        sid = created_session["id"]
        resp = client.get(f"/api/v1/sessions/{sid}", headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json()["id"] == sid

    def test_get_nonexistent_session(self, client, admin_headers):
        resp = client.get("/api/v1/sessions/session-000000000000", headers=admin_headers)
        assert resp.status_code == 404


class TestSessionDelete:
    def test_delete_session(self, client, admin_headers, created_case):
        case_id = created_case["id"]
        sess = client.post(f"/api/v1/cases/{case_id}/sessions", headers=admin_headers).json()
        resp = client.delete(f"/api/v1/sessions/{sess['id']}", headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

        resp2 = client.get(f"/api/v1/sessions/{sess['id']}", headers=admin_headers)
        assert resp2.status_code == 404


class TestSessionMessages:
    def test_empty_messages(self, client, admin_headers, created_session):
        sid = created_session["id"]
        resp = client.get(f"/api/v1/sessions/{sid}/messages", headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json()["total"] == 0

    def test_messages_nonexistent_session(self, client, admin_headers):
        resp = client.get("/api/v1/sessions/session-000000000000/messages", headers=admin_headers)
        assert resp.status_code == 404


class TestSessionStatus:
    def test_get_status(self, client, admin_headers, created_session):
        sid = created_session["id"]
        resp = client.get(f"/api/v1/sessions/{sid}/status", headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["session_id"] == sid
        assert data["status"] == "pending"
        assert data["progress"] == 0

    def test_status_nonexistent_session(self, client, admin_headers):
        resp = client.get("/api/v1/sessions/session-000000000000/status", headers=admin_headers)
        assert resp.status_code == 404
