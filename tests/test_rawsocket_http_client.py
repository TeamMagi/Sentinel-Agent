"""RawHttpClient — TIER_C.md C3: ham TCP üzerinden zamanlama gözlemi.

Network'süz (CLAUDE.md §6): gerçek bir hedefe/internete ASLA gidilmez. Gerçek soket/zamanlama
mekaniğini test edebilmek için `127.0.0.1`'de kendi (ephemeral portlu) TCP sunucumuzu açarız —
`test_auth_browser.py`'nin gerçek bir tarayıcı SÜRECİ başlatmasıyla aynı ruh.
"""
import asyncio
import contextlib

import pytest

from pentestai.models import Scope
from pentestai.net.limits import BudgetExceeded, BudgetTracker
from pentestai.net.replay import ScopeError
from pentestai.policy import PolicyEngine
from pentestai.rawsocket.http_client import RawHttpClient


async def _handle_fast(reader, writer):
    with contextlib.suppress(Exception):
        await asyncio.wait_for(reader.read(4096), timeout=0.5)
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
        await writer.drain()
        writer.close()
        await writer.wait_closed()


async def _handle_hang(reader, writer):
    with contextlib.suppress(Exception):
        await asyncio.wait_for(reader.read(4096), timeout=0.5)
        await asyncio.sleep(2.0)   # istemcinin read_timeout'undan (0.3s) kasıtlı daha uzun
        writer.close()
        await writer.wait_closed()


async def _start(handler):
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


def _scope(port: int) -> Scope:
    return Scope(allowed_hosts=["127.0.0.1"], allowed_ports=[port], allowed_path_prefixes=["/"],
                allowed_methods=["GET", "HEAD", "POST"], destructive_tests=True)


@pytest.mark.asyncio
async def test_fast_response_is_not_timed_out():
    server, port = await _start(_handle_fast)
    try:
        client = RawHttpClient(policy=PolicyEngine(_scope(port)), connect_timeout=2.0)
        raw = b"POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n"
        result = await client.send(f"http://127.0.0.1:{port}", "/", raw_request=raw, read_timeout=1.0)
        assert result.timed_out is False
        assert result.status == 200
        assert result.connect_error == ""
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_hanging_server_is_timed_out():
    server, port = await _start(_handle_hang)
    try:
        client = RawHttpClient(policy=PolicyEngine(_scope(port)), connect_timeout=2.0)
        raw = b"POST / HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n"
        result = await client.send(f"http://127.0.0.1:{port}", "/", raw_request=raw, read_timeout=0.3)
        assert result.timed_out is True
        assert result.status is None
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_unreachable_port_returns_connect_error():
    client = RawHttpClient(policy=PolicyEngine(_scope(1)), connect_timeout=0.3)
    result = await client.send("http://127.0.0.1:1", "/", raw_request=b"x", read_timeout=1.0)
    assert result.connect_error != ""
    assert result.timed_out is False


@pytest.mark.asyncio
async def test_scope_denied_raises_before_touching_socket(monkeypatch):
    def _boom(*a, **kw):
        raise AssertionError("scope reddettiyse open_connection hiç çağrılmamalı")

    monkeypatch.setattr("asyncio.open_connection", _boom)
    scope = Scope(allowed_hosts=["other.test.local"], allowed_ports=[80], allowed_path_prefixes=["/"],
                  destructive_tests=True)
    client = RawHttpClient(policy=PolicyEngine(scope))
    with pytest.raises(ScopeError):
        await client.send("http://127.0.0.1:80", "/", raw_request=b"x", read_timeout=1.0)


@pytest.mark.asyncio
async def test_non_destructive_scope_denies_post(monkeypatch):
    """destructive_tests=False iken POST reddedilir (PolicyEngine'in KENDİ kapısı — ikinci
    savunma katmanını SmugglingOracle ayrıca kontrol eder)."""
    def _boom(*a, **kw):
        raise AssertionError("scope reddettiyse open_connection hiç çağrılmamalı")

    monkeypatch.setattr("asyncio.open_connection", _boom)
    scope = Scope(allowed_hosts=["127.0.0.1"], allowed_ports=[80], allowed_path_prefixes=["/"],
                  destructive_tests=False)
    client = RawHttpClient(policy=PolicyEngine(scope))
    with pytest.raises(ScopeError):
        await client.send("http://127.0.0.1:80", "/", raw_request=b"x", read_timeout=1.0)


@pytest.mark.asyncio
async def test_budget_exceeded_raises_before_touching_socket(monkeypatch):
    def _boom(*a, **kw):
        raise AssertionError("budget aşıldıysa open_connection hiç çağrılmamalı")

    monkeypatch.setattr("asyncio.open_connection", _boom)
    client = RawHttpClient(budget=BudgetTracker(max_total_requests=0))
    with pytest.raises(BudgetExceeded):
        await client.send("http://127.0.0.1:80", "/", raw_request=b"x", read_timeout=1.0)
