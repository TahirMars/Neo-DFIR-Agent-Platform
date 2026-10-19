"""报告生成、列表、更新、删除与下载测试。"""
import pytest


def _seed_messages(client, admin_headers, session_id: str, n: int = 3):
    """向会话插入一些对话消息以便生成报告。"""
    from src.services.session_store import add_session_message
    for i in range(n):
        add_session_message(session_id, "user", f"用户消息 {i}")
        add_session_message(session_id, "assistant", f"## 分析结果 {i}\n\n这是第 {i} 轮分析报告内容。")


class TestReportGenerate:
    def test_generate_report(self, client, admin_headers, created_session):
        sid = created_session["id"]
        _seed_messages(client, admin_headers, sid)
        resp = client.post(f"/api/v1/sessions/{sid}/reports", json={"title": "测试报告"}, headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["report"]["title"] == "测试报告"
        assert data["report"]["session_id"] == sid
        assert len(data["report"]["content"]) > 0

    def test_generate_report_empty_chat(self, client, admin_headers, created_session):
        sid = created_session["id"]
        resp = client.post(f"/api/v1/sessions/{sid}/reports", json={}, headers=admin_headers)
        assert resp.status_code == 400

    def test_generate_report_nonexistent_session(self, client, admin_headers):
        resp = client.post("/api/v1/sessions/session-000000000000/reports", json={}, headers=admin_headers)
        assert resp.status_code == 404


class TestReportList:
    def test_list_session_reports(self, client, admin_headers, created_session):
        sid = created_session["id"]
        _seed_messages(client, admin_headers, sid)
        client.post(f"/api/v1/sessions/{sid}/reports", json={"title": "报告1"}, headers=admin_headers)
        client.post(f"/api/v1/sessions/{sid}/reports", json={"title": "报告2"}, headers=admin_headers)

        resp = client.get(f"/api/v1/sessions/{sid}/reports", headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 2

    def test_list_my_reports(self, client, admin_headers, created_session):
        sid = created_session["id"]
        _seed_messages(client, admin_headers, sid)
        client.post(f"/api/v1/sessions/{sid}/reports", json={"title": "我的报告"}, headers=admin_headers)

        resp = client.get("/api/v1/reports", headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json()["total"] >= 1


class TestReportDetail:
    def _create_report(self, client, admin_headers, session_id):
        _seed_messages(client, admin_headers, session_id)
        return client.post(f"/api/v1/sessions/{session_id}/reports", json={"title": "详情测试"}, headers=admin_headers).json()["report"]

    def test_get_report(self, client, admin_headers, created_session):
        sid = created_session["id"]
        report = self._create_report(client, admin_headers, sid)
        resp = client.get(f"/api/v1/sessions/{sid}/reports/{report['id']}", headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json()["id"] == report["id"]

    def test_get_nonexistent_report(self, client, admin_headers, created_session):
        sid = created_session["id"]
        resp = client.get(f"/api/v1/sessions/{sid}/reports/report-000000000000", headers=admin_headers)
        assert resp.status_code == 404


class TestReportUpdate:
    def test_update_report_title(self, client, admin_headers, created_session):
        sid = created_session["id"]
        _seed_messages(client, admin_headers, sid)
        report = client.post(f"/api/v1/sessions/{sid}/reports", json={"title": "旧标题"}, headers=admin_headers).json()["report"]

        resp = client.put(f"/api/v1/sessions/{sid}/reports/{report['id']}", json={"title": "新标题"}, headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json()["report"]["title"] == "新标题"


class TestReportDelete:
    def test_delete_report(self, client, admin_headers, created_session):
        sid = created_session["id"]
        _seed_messages(client, admin_headers, sid)
        report = client.post(f"/api/v1/sessions/{sid}/reports", json={"title": "待删"}, headers=admin_headers).json()["report"]

        resp = client.delete(f"/api/v1/sessions/{sid}/reports/{report['id']}", headers=admin_headers)
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

        resp2 = client.get(f"/api/v1/sessions/{sid}/reports/{report['id']}", headers=admin_headers)
        assert resp2.status_code == 404


class TestReportDownload:
    def test_download_md(self, client, admin_headers, created_session):
        sid = created_session["id"]
        _seed_messages(client, admin_headers, sid)
        report = client.post(f"/api/v1/sessions/{sid}/reports", json={"title": "下载测试"}, headers=admin_headers).json()["report"]

        resp = client.get(f"/api/v1/sessions/{sid}/reports/{report['id']}/download?format=md", headers=admin_headers)
        assert resp.status_code == 200
        assert "text/markdown" in resp.headers.get("content-type", "")
        assert len(resp.text) > 0
