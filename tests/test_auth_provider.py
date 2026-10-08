"""AuthProvider — TokenAuthProvider'ın login POST'u da PolicyEngine kapısından geçmeli.

Network'süz (CLAUDE.md §6): httpx.MockTransport ile.
"""
import httpx
import pytest

from pentestai.auth.browser import BrowserAuthProvider
from pentestai.auth.provider import TokenAuthProvider, build_auth_provider
from pentestai.models import Scope
from pentestai.net.replay import ScopeError
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"


def _scope(**kw):
    base = dict(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
               allowed_methods=["GET", "HEAD"], destructive_tests=False)
    base.update(kw)
    return Scope(**base)


@pytest.mark.asyncio
async def test_token_provider_without_policy_behaves_as_before():
    def handler(request):
        return httpx.Response(200, json={"authentication": {"token": "tok-123"}})

    provider = TokenAuthProvider(
        f"{BASE}/rest/user/login", {"email": "a@test.local", "password": "x"},
        {"kind": "bearer", "from": "json:authentication.token"},
        transport=httpx.MockTransport(handler),
    )
    state = await provider.acquire()
    assert state.headers == {"Authorization": "Bearer tok-123"}


@pytest.mark.asyncio
async def test_token_provider_allows_login_post_even_when_post_not_in_test_methods():
    # scope yalnızca GET/HEAD test method'una izin veriyor (destructive_tests=False) — login POST
    # yine de purpose="auth" ile geçmeli (method/destructive kapısı auth'a uygulanmaz).
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(200, json={"authentication": {"token": "tok-abc"}})

    provider = TokenAuthProvider(
        f"{BASE}/rest/user/login", {"email": "a@test.local", "password": "x"},
        {"kind": "bearer", "from": "json:authentication.token"},
        transport=httpx.MockTransport(handler),
        policy=PolicyEngine(_scope()),
    )
    state = await provider.acquire()
    assert state.headers == {"Authorization": "Bearer tok-abc"}
    assert calls == [f"{BASE}/rest/user/login"]


@pytest.mark.asyncio
async def test_token_provider_denies_login_url_outside_host_scope():
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(200, json={"authentication": {"token": "should-not-be-used"}})

    provider = TokenAuthProvider(
        "http://evil.example/rest/user/login", {"email": "a@test.local", "password": "x"},
        {"kind": "bearer", "from": "json:authentication.token"},
        transport=httpx.MockTransport(handler),
        policy=PolicyEngine(_scope()),
    )
    with pytest.raises(ScopeError):
        await provider.acquire()
    assert calls == []   # istek hiç gönderilmedi


@pytest.mark.asyncio
async def test_token_provider_denies_login_url_outside_path_scope():
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(200, json={"authentication": {"token": "x"}})

    provider = TokenAuthProvider(
        f"{BASE}/admin/login", {"email": "a@test.local", "password": "x"},
        {"kind": "bearer", "from": "json:authentication.token"},
        transport=httpx.MockTransport(handler),
        policy=PolicyEngine(_scope(allowed_path_prefixes=["/rest/"])),
    )
    with pytest.raises(ScopeError):
        await provider.acquire()
    assert calls == []


@pytest.mark.asyncio
async def test_build_auth_provider_wires_policy_and_transport_for_token_type():
    def handler(request):
        return httpx.Response(200, json={"authentication": {"token": "wired"}})

    provider = build_auth_provider(
        {"type": "token", "login_url": f"{BASE}/rest/user/login",
         "credentials": {"email": "a@test.local", "password": "x"},
         "token_location": {"kind": "bearer", "from": "json:authentication.token"}},
        policy=PolicyEngine(_scope()), transport=httpx.MockTransport(handler),
    )
    state = await provider.acquire()
    assert state.headers == {"Authorization": "Bearer wired"}


def test_build_auth_provider_wires_browser_type():
    provider = build_auth_provider(
        {"type": "browser", "login_url": f"{BASE}/login",
         "credentials": {"email": "a@test.local", "password": "x"},
         "mfa_totp_secret": "JBSWY3DPEHPK3PXP", "headless": False},
        policy=PolicyEngine(_scope()),
    )
    assert isinstance(provider, BrowserAuthProvider)
    assert provider.login_url == f"{BASE}/login"
    assert provider.mfa_totp_secret == "JBSWY3DPEHPK3PXP"
    assert provider.headless is False


@pytest.mark.asyncio
async def test_build_auth_provider_static_ignores_policy_and_transport():
    # static/storagestate ağa hiç çıkmaz — policy/transport verilse de kullanılmaz, hata olmaz.
    provider = build_auth_provider(
        {"type": "static", "headers": {"X-Api-Key": "k"}, "cookies": {}},
        policy=PolicyEngine(_scope()), transport=httpx.MockTransport(lambda r: httpx.Response(200)),
    )
    state = await provider.acquire()
    assert state.headers == {"X-Api-Key": "k"}
