"""
深信服威胁情报接口连通性测试与 SSL 诊断。
运行: pytest tests/test_sangfor_ti.py -v -s
"""
import asyncio
import json
import ssl
import socket

import httpx
import pytest

from src.tools.threat_intel.tisangfor import (
    SANGFOR_BASE,
    _b64_ioc,
    _make_ssl_context,
    _REPUTATION_MAP,
    _request,
    query_domain_sangfor,
    query_ip_sangfor,
    query_hash_sangfor,
)

SANGFOR_HOST = "ti.sangfor.com.cn"
SANGFOR_PORT = 443


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------

def _get_env_credentials() -> tuple[str, str]:
    """从环境变量或 .env 读取深信服凭据，缺失则跳过。"""
    from src.core.config import get_settings
    s = get_settings()
    cookie = s.sangfor_cookie or ""
    csrf = s.sangfor_csrf_token or ""
    if not cookie or not csrf:
        pytest.skip("未配置 SANGFOR_COOKIE / SANGFOR_CSRF_TOKEN，跳过实际调用测试")
    return cookie, csrf


# ---------------------------------------------------------------------------
# SSL / TLS 诊断
# ---------------------------------------------------------------------------

class TestSangforSSLDiag:
    """SSL 握手诊断（不需要凭据，直接探测服务端 TLS 能力）。"""

    def test_raw_socket_default_ctx_expected_to_fail(self):
        """默认 SSL 上下文因 SECLEVEL=2 排除深信服所需的非 PFS 套件，预期会失败。"""
        ctx = ssl.create_default_context()
        with socket.create_connection((SANGFOR_HOST, SANGFOR_PORT), timeout=10) as sock:
            with pytest.raises(ssl.SSLError, match="HANDSHAKE_FAILURE|handshake"):
                ctx.wrap_socket(sock, server_hostname=SANGFOR_HOST)

    def test_tls_handshake_no_verify(self):
        """用禁用验证的上下文测试（模拟当前 tisangfor.py 的做法）。"""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((SANGFOR_HOST, SANGFOR_PORT), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=SANGFOR_HOST) as ssock:
                    print(f"\n[OK] TLS 握手成功 (CERT_NONE)")
                    print(f"  协议版本: {ssock.version()}")
                    print(f"  密码套件: {ssock.cipher()}")
        except ssl.SSLError as e:
            print(f"\n[FAIL] CERT_NONE 上下文握手失败: {e}")
            # 尝试放宽密码套件
            self._try_relaxed_ciphers(e)

    def _try_relaxed_ciphers(self, original_error: ssl.SSLError):
        """尝试放宽密码套件来解决握手失败。"""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
        try:
            with socket.create_connection((SANGFOR_HOST, SANGFOR_PORT), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=SANGFOR_HOST) as ssock:
                    print(f"\n[OK] 放宽密码套件后握手成功!")
                    print(f"  协议版本: {ssock.version()}")
                    print(f"  密码套件: {ssock.cipher()}")
                    print(f"  → 修复方案: 在 tisangfor.py 中使用 set_ciphers('DEFAULT:@SECLEVEL=1')")
        except ssl.SSLError as e2:
            print(f"\n[FAIL] 放宽密码套件后仍失败: {e2}")
            self._try_all_ciphers()

    def _try_all_ciphers(self):
        """最后手段：尝试所有可用密码套件。"""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("ALL:@SECLEVEL=0")
        try:
            with socket.create_connection((SANGFOR_HOST, SANGFOR_PORT), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=SANGFOR_HOST) as ssock:
                    print(f"\n[OK] ALL ciphers SECLEVEL=0 握手成功!")
                    print(f"  协议版本: {ssock.version()}")
                    print(f"  密码套件: {ssock.cipher()}")
                    print(f"  → 需要的密码套件安全等级较低，建议升级服务端或使用 SECLEVEL=0")
        except ssl.SSLError as e3:
            print(f"\n[FAIL] 所有密码套件均失败: {e3}")
            print("  可能原因: 服务端不可达 / 需要特定 TLS 扩展 / 防火墙拦截")

    def test_make_ssl_context_handshake_succeeds(self):
        """验证修复后的 _make_ssl_context 可以与深信服服务器完成 TLS 握手。"""
        ctx = _make_ssl_context()
        with socket.create_connection((SANGFOR_HOST, SANGFOR_PORT), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=SANGFOR_HOST) as ssock:
                assert ssock.version() is not None
                cipher = ssock.cipher()
                print(f"\n[OK] _make_ssl_context 握手成功")
                print(f"  协议: {ssock.version()}, 套件: {cipher}")
                assert cipher is not None

    def test_httpx_default_ssl(self):
        """用 httpx 默认配置尝试请求（不带凭据，仅测连通性）。"""
        url = SANGFOR_BASE + "domain/reputation?query=" + _b64_ioc("baidu.com")

        async def _do():
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(url)
                return r.status_code

        try:
            code = asyncio.run(_do())
            print(f"\n[OK] httpx 默认请求返回 HTTP {code}")
        except httpx.ConnectError as e:
            print(f"\n[FAIL] httpx 默认连接失败: {e}")
            if "HANDSHAKE_FAILURE" in str(e) or "SSL" in str(e).upper():
                print("  确认是 SSL 握手问题")

    def test_httpx_with_relaxed_ssl(self):
        """用放宽 SSL 配置的 httpx 请求。"""
        url = SANGFOR_BASE + "domain/reputation?query=" + _b64_ioc("baidu.com")

        async def _do():
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
            async with httpx.AsyncClient(verify=ctx, timeout=15) as client:
                r = await client.get(url)
                return r.status_code

        try:
            code = asyncio.run(_do())
            print(f"\n[OK] httpx 放宽 SSL 请求返回 HTTP {code}")
        except Exception as e:
            print(f"\n[FAIL] httpx 放宽 SSL 请求失败: {e}")


# ---------------------------------------------------------------------------
# 单元测试（纯逻辑，不依赖网络）
# ---------------------------------------------------------------------------

class TestSangforPureLogic:
    """不依赖网络的纯逻辑测试。"""

    def test_b64_ioc_encoding(self):
        assert _b64_ioc("baidu.com") == "YmFpZHUuY29t"
        assert _b64_ioc("192.168.1.1") == "MTkyLjE2OC4xLjE="
        assert _b64_ioc("evil.example.com") == "ZXZpbC5leGFtcGxlLmNvbQ=="

    @pytest.mark.parametrize("reputation,expected", [
        ("1", "benign"),
        ("0", "malicious"),
        ("3", "suspicious"),
        ("2", "unknown"),
    ])
    def test_reputation_map(self, reputation, expected):
        assert _REPUTATION_MAP.get(reputation, "unknown") == expected

    def test_reputation_map_unknown_key(self):
        assert _REPUTATION_MAP.get("999", "unknown") == "unknown"
        assert _REPUTATION_MAP.get("", "unknown") == "unknown"


# ---------------------------------------------------------------------------
# 集成测试（需要网络 + 凭据）
# ---------------------------------------------------------------------------

class TestSangforIntegration:
    """需要配置 SANGFOR_COOKIE 和 SANGFOR_CSRF_TOKEN 的实际查询测试。"""

    @pytest.mark.asyncio
    async def test_query_domain(self):
        cookie, csrf = _get_env_credentials()
        result = await query_domain_sangfor(cookie, csrf, "baidu.com", timeout=15)
        print(f"\n域名查询结果: {json.dumps(result, ensure_ascii=False, indent=2, default=str)}")
        assert result["verdict"] in ("malicious", "suspicious", "unknown", "benign")
        assert "labels" in result
        assert "related_files" in result
        assert isinstance(result["related_files"], list)

    @pytest.mark.asyncio
    async def test_query_malicious_domain(self):
        cookie, csrf = _get_env_credentials()
        result = await query_domain_sangfor(cookie, csrf, "govmm.org", timeout=15)
        print(f"\n恶意域名查询结果: {json.dumps(result, ensure_ascii=False, indent=2, default=str)}")
        assert "verdict" in result
        assert "labels" in result
        assert "description" in result
        if result["verdict"] == "malicious":
            assert result.get("first_found_time") or result.get("description")

    @pytest.mark.asyncio
    async def test_query_ip(self):
        cookie, csrf = _get_env_credentials()
        result = await query_ip_sangfor(cookie, csrf, "8.8.8.8", timeout=15)
        print(f"\nIP 查询结果: {json.dumps(result, ensure_ascii=False, indent=2, default=str)}")
        assert result["verdict"] in ("malicious", "suspicious", "unknown", "benign")
        assert "geo" in result
        assert "related_files" in result

    @pytest.mark.asyncio
    async def test_query_hash(self):
        cookie, csrf = _get_env_credentials()
        eicar_sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        result = await query_hash_sangfor(cookie, csrf, eicar_sha256, timeout=30)
        print(f"\n哈希查询结果: {json.dumps(result, ensure_ascii=False, indent=2, default=str)}")
        assert "verdict" in result
        assert "file_info" in result
        assert "dynamic_analysis" in result
        assert "network_behavior" in result
        assert "related_files" in result

    @pytest.mark.asyncio
    async def test_request_returns_error_on_bad_creds(self):
        """使用无效凭据，应返回 error 或非成功响应。"""
        url = SANGFOR_BASE + "domain/reputation?query=" + _b64_ioc("baidu.com")
        result = await _request(url, "bad-cookie", "bad-csrf", timeout=10)
        print(f"\n无效凭据请求结果: {result}")
        assert isinstance(result, dict)
