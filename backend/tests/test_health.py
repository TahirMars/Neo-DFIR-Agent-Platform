"""健康检查与基础路由测试。"""


def test_health_check(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_unknown_route_returns_404(client):
    resp = client.get("/api/v1/nonexistent")
    assert resp.status_code in (404, 405)


def test_request_id_header(client):
    resp = client.get("/health")
    assert "x-request-id" in resp.headers


def test_custom_request_id(client):
    resp = client.get("/health", headers={"X-Request-Id": "test-req-001"})
    assert resp.headers.get("x-request-id") == "test-req-001"
