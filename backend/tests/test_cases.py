"""案件 CRUD 测试。"""
import pytest


class TestCaseList:
    def test_list_cases_empty(self, client, admin_headers):
        resp = client.get("/api/v1/projects/proj1/cases", headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert isinstance(data["items"], list)

    def test_list_cases_nonexistent_project(self, client, admin_headers):
        resp = client.get("/api/v1/projects/nonexistent/cases", headers=admin_headers)
        assert resp.status_code in (200, 403)


class TestCaseCreate:
    def test_create_case(self, client, admin_headers):
        resp = client.post("/api/v1/projects/proj1/cases", json={"name": "案件A"}, headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "案件A"
        assert data["id"].startswith("case-")
        assert data["project_id"] == "proj1"

    def test_create_case_default_name(self, client, admin_headers):
        resp = client.post("/api/v1/projects/proj1/cases", json={}, headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json()["name"] == "未命名案件"


class TestCaseGet:
    def test_get_case(self, client, admin_headers, created_case):
        case_id = created_case["id"]
        resp = client.get(f"/api/v1/cases/{case_id}", headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json()["id"] == case_id

    def test_get_nonexistent_case(self, client, admin_headers):
        resp = client.get("/api/v1/cases/case-000000000000", headers=admin_headers)
        assert resp.status_code == 404


class TestCaseDelete:
    def test_delete_case(self, client, admin_headers):
        case = client.post("/api/v1/projects/proj1/cases", json={"name": "待删除"}, headers=admin_headers).json()
        resp = client.delete(f"/api/v1/cases/{case['id']}", headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

        resp2 = client.get(f"/api/v1/cases/{case['id']}", headers=admin_headers)
        assert resp2.status_code == 404

    def test_delete_nonexistent_case(self, client, admin_headers):
        resp = client.delete("/api/v1/cases/case-000000000000", headers=admin_headers)
        assert resp.status_code == 404
