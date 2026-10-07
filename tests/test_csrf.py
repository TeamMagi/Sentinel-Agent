"""CSRFProvider + Replayer entegrasyonu — durum-değiştiren isteğe taze token ekleme. B1."""
import json

import httpx
import pytest

from pentestai.models import Actor, AuthState, CapturedRequest, CSRFConfig, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"


def handler(request):
    if request.url.path == "/csrf-token":
        return httpx.Response(200, json={"csrfToken": "tok-abc123"})
    if request.url.path == "/api/orders/1":
        token_header = request.headers.get("x-csrf-token")
        if token_header != "tok-abc123":
            return httpx.Response(403, json={"error": "invalid csrf"})
        return httpx.Response(200, json={"status": "ok"})
    return httpx.Response(404, json={})


def _setup(csrf_cfg=None):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["GET", "HEAD", "PUT"], destructive_tests=True)
    store = SessionStore(transport=httpx.MockTransport(handler))
    actor = Actor(name="user_A", auth=AuthState(
        headers={"Authorization": "Bearer T"},
        csrf=csrf_cfg,
    ))
    session = store.create(actor)
    replayer = Replayer(PolicyEngine(scope))
    return store, replayer, session


@pytest.mark.asyncio
async def test_csrf_token_attached_to_header_for_state_changing_request():
    cfg = CSRFConfig(fetch_url=f"{BASE}/csrf-token", location="header",
                     field_name="X-CSRF-Token", extract="json:csrfToken")
    store, replayer, session = _setup(cfg)
    req = CapturedRequest(method="PUT", url=f"{BASE}/api/orders/1")
    resp = await replayer.replay(req, session)
    assert resp.status == 200
    await store.aclose_all()


@pytest.mark.asyncio
async def test_no_csrf_config_means_no_token_attached():
    store, replayer, session = _setup(csrf_cfg=None)
    req = CapturedRequest(method="PUT", url=f"{BASE}/api/orders/1")
    resp = await replayer.replay(req, session)
    assert resp.status == 403   # token yok → sunucu reddetti
    await store.aclose_all()


@pytest.mark.asyncio
async def test_skip_csrf_forces_request_without_token():
    cfg = CSRFConfig(fetch_url=f"{BASE}/csrf-token", location="header",
                     field_name="X-CSRF-Token", extract="json:csrfToken")
    store, replayer, session = _setup(cfg)
    req = CapturedRequest(method="PUT", url=f"{BASE}/api/orders/1")
    resp = await replayer.replay(req, session, skip_csrf=True)
    assert resp.status == 403
    await store.aclose_all()


@pytest.mark.asyncio
async def test_csrf_body_location_merges_json_field():
    def body_handler(request):
        if request.url.path == "/csrf-token":
            return httpx.Response(200, json={"csrfToken": "body-tok"})
        body = json.loads(request.content or b"{}")
        if body.get("_csrf") != "body-tok":
            return httpx.Response(403, json={"error": "invalid csrf"})
        return httpx.Response(200, json={"status": "ok"})

    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["PUT"], destructive_tests=True)
    store = SessionStore(transport=httpx.MockTransport(body_handler))
    cfg = CSRFConfig(fetch_url=f"{BASE}/csrf-token", location="body", field_name="_csrf",
                     extract="json:csrfToken")
    actor = Actor(name="user_A", auth=AuthState(csrf=cfg))
    session = store.create(actor)
    replayer = Replayer(PolicyEngine(scope))
    req = CapturedRequest(method="PUT", url=f"{BASE}/api/x", body=json.dumps({"a": 1}).encode())
    resp = await replayer.replay(req, session)
    assert resp.status == 200
    await store.aclose_all()


@pytest.mark.asyncio
async def test_csrf_fetch_denied_by_scope_never_reaches_transport():
    calls = []

    def tracking_handler(request):
        calls.append(str(request.url))
        if request.url.path == "/api/orders/1":
            return httpx.Response(200, json={"status": "ok-no-csrf-needed"})
        return httpx.Response(200, json={"csrfToken": "should-not-be-used"})

    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["PUT"], destructive_tests=True)
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(tracking_handler))
    # fetch_url scope dışı bir host'u gösteriyor (ör. keşiften/config'ten yanlış gelmiş) —
    # istek HİÇ gönderilmemeli (hem scope kaçışı hem cookie sızıntısı riski, CLAUDE.md §5).
    cfg = CSRFConfig(fetch_url="http://evil.example/csrf-token", extract="json:csrfToken")
    actor = Actor(name="user_A", auth=AuthState(csrf=cfg))
    session = store.create(actor)
    replayer = Replayer(PolicyEngine(scope))
    req = CapturedRequest(method="PUT", url=f"{BASE}/api/orders/1")
    resp = await replayer.replay(req, session)
    assert resp.status == 200
    assert calls == [f"{BASE}/api/orders/1"]   # csrf-token isteği hiç gönderilmedi
    await store.aclose_all()


@pytest.mark.asyncio
async def test_csrf_fetch_failure_is_silent():
    def failing_handler(request):
        if request.url.path == "/csrf-token":
            return httpx.Response(500, json={"error": "boom"})
        return httpx.Response(200, json={"status": "ok-no-csrf-needed"})

    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["PUT"], destructive_tests=True)
    store = SessionStore(transport=httpx.MockTransport(failing_handler))
    cfg = CSRFConfig(fetch_url=f"{BASE}/csrf-token", extract="json:csrfToken")
    actor = Actor(name="user_A", auth=AuthState(csrf=cfg))
    session = store.create(actor)
    replayer = Replayer(PolicyEngine(scope))
    req = CapturedRequest(method="PUT", url=f"{BASE}/api/x")
    resp = await replayer.replay(req, session)   # fetch 500 → sessizce atla, çökme
    assert resp.status == 200
    await store.aclose_all()
