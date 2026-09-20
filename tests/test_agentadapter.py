"""AgentAdapter — Sentinel'i bir ajan/MCP hedefine bağlayan bileşen (AS-1). DESIGN.md §10.6.

Ağsız (MockTransport): ajan hedefinin JSON trace yanıtı `AgentTrace`/`ToolCall`'a normalize
ediliyor mu; bozuk/eksik alanlar crash etmeden güvenli varsayılana düşüyor mu.
"""

import httpx
import pytest

from pentestai.agentadapter import HttpAgentAdapter, StaticAgentAdapter
from pentestai.models import Actor, AgentTrace, AuthState, Scope, ToolCall
from pentestai.net import Replayer, SessionStore
from pentestai.policy import PolicyEngine

BASE = "http://agent.local"


def _policy():
    scope = Scope(allowed_hosts=["agent.local"], allowed_ports=[80], allowed_path_prefixes=["/"],
                  allowed_methods=["GET", "POST"], destructive_tests=True)
    return PolicyEngine(scope)


def _store_session(handler):
    store = SessionStore(transport=httpx.MockTransport(handler))
    actor = Actor(name="tester", auth=AuthState(headers={"Authorization": "Bearer T"}))
    return store, store.create(actor)


@pytest.mark.asyncio
async def test_http_adapter_parses_well_formed_trace():
    def handler(request):
        body = {"steps": [
            {"tool": "web.search", "args": {"q": "test"}, "output": "sonuç metni",
             "source": "untrusted_content"},
            {"tool": "email.send", "args": {"to": "x@y.com"}, "source": "agent",
             "target_url": "https://mail.example/send"},
        ]}
        return httpx.Response(200, json=body)

    store, session = _store_session(handler)
    adapter = HttpAgentAdapter(Replayer(_policy()), BASE)
    trace = await adapter.capture_trace("görevi yap", session, user_intent="hiçbir şey isteme")
    assert isinstance(trace, AgentTrace)
    assert len(trace.calls) == 2
    assert trace.calls[0].name == "web.search"
    assert trace.calls[0].source == "untrusted_content"
    assert trace.calls[0].turn == 0
    assert trace.calls[1].target_url == "https://mail.example/send"
    assert trace.calls[1].turn == 1
    await store.aclose_all()


@pytest.mark.asyncio
async def test_http_adapter_defaults_malformed_steps_safely():
    def handler(request):
        # source geçersiz + args liste (dict değil) + isimsiz adım → hepsi güvenli varsayılana düşmeli.
        body = {"steps": [
            {"tool": "fs.write", "args": ["not", "a", "dict"], "source": "not-a-real-source"},
            {"args": {}},          # tool adı yok → atlanır
            "not-a-dict-step",     # tip hatası → atlanır
        ]}
        return httpx.Response(200, json=body)

    store, session = _store_session(handler)
    adapter = HttpAgentAdapter(Replayer(_policy()), BASE)
    trace = await adapter.capture_trace("görev", session)
    assert len(trace.calls) == 1
    assert trace.calls[0].name == "fs.write"
    assert trace.calls[0].args == {}
    assert trace.calls[0].source == "agent"
    await store.aclose_all()


@pytest.mark.asyncio
async def test_http_adapter_empty_body_yields_empty_trace():
    def handler(request):
        return httpx.Response(200, json={})

    store, session = _store_session(handler)
    adapter = HttpAgentAdapter(Replayer(_policy()), BASE)
    trace = await adapter.capture_trace("görev", session)
    assert trace.calls == []
    await store.aclose_all()


@pytest.mark.asyncio
async def test_static_adapter_returns_fixed_trace_unchanged():
    fixed = AgentTrace(task="x", calls=[ToolCall(name="fs.write", args={}, turn=0)])
    adapter = StaticAgentAdapter(fixed)
    store, session = _store_session(lambda r: httpx.Response(500))
    trace = await adapter.capture_trace("başka bir görev", session)
    assert trace is fixed
    await store.aclose_all()
