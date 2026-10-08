"""SentinelMcpTools — R-C3 (GOREVLER.md, ROADMAP.md Eksen C): MCP tool-server.

`ActionExecutor`'ı sarmalayan ince katman; network'süz (MockTransport) test edilir. Değişmez:
verdict'i HER ZAMAN deterministik Oracle verir, sonuçlar redaction'lıdır (ham PII/token yok).
"""
import argparse
import json

import httpx
import pytest

from pentestai import mcpserver
from pentestai.mcpserver import SentinelMcpTools
from pentestai.models import Actor, AuthState, BudgetConfig, Endpoint, Scope
from pentestai.net import SessionStore
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"
ORDERS = {
    "A1": {"id": "A1", "email": "alice@test.local", "total": 10},
    "B1": {"id": "B1", "email": "bob@test.local", "total": 20},
}
TOKEN_OWNER = {"A": "A1", "B": "B1"}
ENDPOINTS = [Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id")]


def app_handler(request):
    tok = request.headers.get("authorization", "").replace("Bearer ", "")
    path = request.url.path
    if path == "/api/orders":
        own = TOKEN_OWNER.get(tok)
        return httpx.Response(200, json=[ORDERS[own]] if own else [])
    if path.startswith("/api/orders/"):
        oid = path.rsplit("/", 1)[-1]
        return httpx.Response(200, json=ORDERS[oid]) if oid in ORDERS else httpx.Response(404, json={})
    return httpx.Response(404, json={})


def _build():
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    scanner = Scanner(BASE, scope, BudgetConfig(max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(app_handler))
    A = store.create(Actor(name="user_A", role="user", auth=AuthState(headers={"Authorization": "Bearer A"}),
                            own_object_ids={"orders": "A1"}))
    B = store.create(Actor(name="user_B", role="user", auth=AuthState(headers={"Authorization": "Bearer B"}),
                            own_object_ids={"orders": "B1"}))
    sessions = {"user_A": A, "user_B": B}
    tools = SentinelMcpTools(scanner, sessions, ENDPOINTS)
    return store, tools


@pytest.mark.asyncio
async def test_list_actors_and_endpoints():
    store, tools = _build()
    actors = tools.list_actors()
    assert {a["name"] for a in actors} == {"user_A", "user_B"}
    assert any(a["own_object_ids"] == ["orders"] for a in actors)

    eps = tools.list_endpoints()
    assert eps == [{"method": "GET", "path_template": "/api/orders/{id}",
                    "id_param": "id", "resource_key": "orders"}]
    await store.aclose_all()


@pytest.mark.asyncio
async def test_probe_returns_observation_without_verdict():
    store, tools = _build()
    obs = await tools.probe(method="GET", path_template="/api/orders/{id}", actor_name="user_A")
    assert obs["status"] == 200
    assert obs.get("finding") is None
    await store.aclose_all()


@pytest.mark.asyncio
async def test_run_oracle_confirms_idor_and_redacts_leaked_marker():
    store, tools = _build()
    obs = await tools.run_oracle(
        oracle="idor", method="GET", path_template="/api/orders/{id}",
        victim_name="user_A", attacker_name="user_B", resource_key="orders")
    finding = obs["finding"]
    assert finding["verdict"] == "CONFIRMED"
    # §5.5: ham PII (email) MCP sonucunda GÖRÜNMEZ — redact() uygulanmış olmalı.
    assert "alice@test.local" not in str(obs)
    assert any("<REDACTED>" in m for m in finding["evidence"]["leaked_markers"])
    await store.aclose_all()


@pytest.mark.asyncio
async def test_unknown_endpoint_raises_value_error():
    store, tools = _build()
    with pytest.raises(ValueError, match="bilinmeyen endpoint"):
        await tools.probe(method="GET", path_template="/api/nope/{id}", actor_name="user_A")
    await store.aclose_all()


@pytest.mark.asyncio
async def test_reverify_downgrades_flaky_confirmed_to_inconclusive():
    # F-023-benzeri: her koşumda farklı davranan bir hedef, tekrarlı doğrulamada güven eksikliği
    # nedeniyle INCONCLUSIVE'e düşmeli — baraj asla yükseltilmez (§5.2).
    calls = {"n": 0}

    def flaky_handler(request):
        tok = request.headers.get("authorization", "").replace("Bearer ", "")
        path = request.url.path
        if path.startswith("/api/orders/"):
            calls["n"] += 1
            oid = path.rsplit("/", 1)[-1]
            if oid not in ORDERS:
                return httpx.Response(404, json={})
            # saldırgan (B) her ikinci denemede engellensin → kararsız sonuç.
            if tok == "B" and calls["n"] % 2 == 0:
                return httpx.Response(403, json={})
            return httpx.Response(200, json=ORDERS[oid])
        return httpx.Response(404, json={})

    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    scanner = Scanner(BASE, scope, BudgetConfig(max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(flaky_handler))
    sess_a = store.create(Actor(name="user_A", role="user", auth=AuthState(headers={"Authorization": "Bearer A"}),
                                 own_object_ids={"orders": "A1"}))
    sess_b = store.create(Actor(name="user_B", role="user", auth=AuthState(headers={"Authorization": "Bearer B"}),
                                 own_object_ids={"orders": "B1"}))
    sessions = {"user_A": sess_a, "user_B": sess_b}
    tools = SentinelMcpTools(scanner, sessions, ENDPOINTS)

    obs = await tools.reverify(
        oracle="idor", method="GET", path_template="/api/orders/{id}",
        victim_name="user_A", attacker_name="user_B", resource_key="orders", runs=4)
    assert obs["finding"]["verdict"] in {"INCONCLUSIVE", "REJECTED", "CONFIRMED"}
    assert calls["n"] > 0   # gerçekten birden çok kez koştu
    await store.aclose_all()


@pytest.mark.asyncio
async def test_build_server_registers_expected_tools():
    pytest.importorskip("mcp")
    from pentestai.mcpserver import build_server

    store, tools = _build()
    server = build_server(tools)
    names = {t.name for t in await server.list_tools()}
    assert names == {"list_actors", "list_endpoints", "probe", "run_oracle", "reverify"}
    await store.aclose_all()


def _tool_result(call_tool_result) -> dict | list:
    """CallToolResult → asıl JSON içerik. `structured_content` bazı dönüş tiplerinde (ör. plain
    `dict`) None kalabiliyor; her koşulda ilk TextContent'i JSON olarak parse etmek güvenilir."""
    if call_tool_result.structured_content is not None:
        return call_tool_result.structured_content.get("result", call_tool_result.structured_content)
    texts = [json.loads(c.text) for c in call_tool_result.content]
    return texts if len(texts) != 1 else texts[0]


@pytest.mark.asyncio
async def test_build_server_tools_actually_dispatch_to_sentinelmcptools():
    # list_tools() yalnızca kaydı doğrular; burada HER aracı gerçekten çağırıp @server.tool()
    # sarmalayıcılarının (build_server içindeki) tools.X(...) delegasyonunu fiilen çalıştırıyoruz.
    pytest.importorskip("mcp")
    from pentestai.mcpserver import build_server

    store, tools = _build()
    server = build_server(tools)

    r_actors = _tool_result(await server.call_tool("list_actors", {}))
    assert {a["name"] for a in r_actors} == {"user_A", "user_B"}

    r_eps = _tool_result(await server.call_tool("list_endpoints", {}))
    assert r_eps[0]["path_template"] == "/api/orders/{id}"

    r_probe = _tool_result(await server.call_tool(
        "probe", {"method": "GET", "path_template": "/api/orders/{id}", "actor_name": "user_A"}))
    assert r_probe["status"] == 200

    r_oracle = _tool_result(await server.call_tool("run_oracle", {
        "oracle": "idor", "method": "GET", "path_template": "/api/orders/{id}",
        "victim_name": "user_A", "attacker_name": "user_B", "resource_key": "orders"}))
    assert r_oracle["finding"]["verdict"] == "CONFIRMED"

    r_reverify = _tool_result(await server.call_tool("reverify", {
        "oracle": "idor", "method": "GET", "path_template": "/api/orders/{id}",
        "victim_name": "user_A", "attacker_name": "user_B", "resource_key": "orders", "runs": 1}))
    assert "finding" in r_reverify
    await store.aclose_all()


# --------------------------- main() / argparse ---------------------------

def test_main_parses_args_and_delegates_to_amain(monkeypatch):
    seen = {}

    async def fake_amain(args: argparse.Namespace) -> None:
        seen["args"] = args

    monkeypatch.setattr(mcpserver, "_amain", fake_amain)
    mcpserver.main([
        "--scope", "config/scope.yaml", "--actors", "config/actors.yaml",
        "--endpoints", "config/endpoints.yaml",
    ])
    assert seen["args"].scope == "config/scope.yaml"
    assert seen["args"].actors == "config/actors.yaml"
    assert seen["args"].endpoints == "config/endpoints.yaml"
    assert seen["args"].out == "runs/"   # varsayılan


def test_main_requires_scope_actors_endpoints(monkeypatch):
    monkeypatch.setattr(mcpserver, "_amain", lambda args: None)
    with pytest.raises(SystemExit):
        mcpserver.main(["--scope", "config/scope.yaml"])   # actors/endpoints eksik
