"""认证、注册与用户管理测试。"""
import pytest


class TestLogin:
    def test_admin_login(self, client):
        resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin123"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["access_token"]
        assert data["username"] == "admin"
        assert data["role"] == "admin"
        assert data["token_type"] == "bearer"

    def test_member_login(self, client):
        resp = client.post("/api/v1/auth/login", json={"username": "member", "password": "member123"})
        assert resp.status_code == 200
        assert resp.json()["role"] == "member"

    def test_wrong_password(self, client):
        resp = client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"})
        assert resp.status_code == 401

    def test_nonexistent_user(self, client):
        resp = client.post("/api/v1/auth/login", json={"username": "ghost", "password": "nope"})
        assert resp.status_code == 401

    def test_empty_body(self, client):
        resp = client.post("/api/v1/auth/login", json={"username": "", "password": ""})
        assert resp.status_code == 422


class TestRegister:
    def test_register_new_user(self, client):
        resp = client.post("/api/v1/auth/register", json={"username": "newuser01", "password": "securePass1"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["username"] == "newuser01"
        assert "user_id" in data

    def test_register_duplicate(self, client):
        client.post("/api/v1/auth/register", json={"username": "dupuser", "password": "securePass1"})
        resp = client.post("/api/v1/auth/register", json={"username": "dupuser", "password": "securePass2"})
        assert resp.status_code == 400

    def test_register_short_password(self, client):
        resp = client.post("/api/v1/auth/register", json={"username": "shortpw", "password": "abc"})
        assert resp.status_code == 422

    def test_register_short_username(self, client):
        resp = client.post("/api/v1/auth/register", json={"username": "ab", "password": "securePass1"})
        assert resp.status_code == 422


class TestMe:
    def test_me_auth_disabled(self, client, admin_headers):
        resp = client.get("/api/v1/auth/me", headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "user_id" in data
        assert "role" in data


class TestUserManagement:
    def test_list_users(self, client, admin_headers):
        resp = client.get("/api/v1/auth/users", headers=admin_headers)
        assert resp.status_code == 200
        users = resp.json()
        assert isinstance(users, list)
        assert any(u["username"] == "admin" for u in users)

    def test_update_user_role(self, client, admin_headers):
        users = client.get("/api/v1/auth/users", headers=admin_headers).json()
        member = next((u for u in users if u["username"] == "member"), None)
        if member:
            resp = client.put(f"/api/v1/auth/users/{member['id']}", json={"role": "member"}, headers=admin_headers)
            assert resp.status_code == 200

    def test_disable_user(self, client, admin_headers):
        client.post("/api/v1/auth/register", json={"username": "todisable", "password": "securePass1"})
        users = client.get("/api/v1/auth/users", headers=admin_headers).json()
        target = next((u for u in users if u["username"] == "todisable"), None)
        if target:
            resp = client.put(f"/api/v1/auth/users/{target['id']}", json={"enabled": False}, headers=admin_headers)
            assert resp.status_code == 200

    def test_list_user_cases(self, client, admin_headers):
        users = client.get("/api/v1/auth/users", headers=admin_headers).json()
        if users:
            resp = client.get(f"/api/v1/auth/users/{users[0]['id']}/cases", headers=admin_headers)
            assert resp.status_code == 200
            assert "items" in resp.json()
