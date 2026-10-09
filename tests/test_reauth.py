"""Mid-scan re-auth (#1) — token süresi dolunca opt-in yeniden yetkilenme. Ağsız (MockTransport).

Değişmez: re-auth OTOMATİK değil (opt-in), aktör KENDİ provider'ıyla tazelenir (izolasyon), ve
en fazla bir kez denenir (sonsuz döngü yok)."""
from __future__ import annotations

import httpx

from pentestai.models import Actor, AuthState, CapturedRequest, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"


def _scope() -> Scope:
    return Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])


async def _fresh_token() -> AuthState:
    return AuthState(headers={"Authorization": "Bearer NEW"})


async def test_reauth_on_401_retries_with_fresh_token():
    def handler(request):
        if request.headers.get("authorization") == "Bearer NEW":
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(401, json={"error": "expired"})

    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    session = store.create(
        Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer OLD"})),
        reauth=_fresh_token)
    rp = Replayer(PolicyEngine(_scope()))
    base = CapturedRequest(method="GET", url=f"{BASE}/api/orders/1")

    norm = await rp.replay(base, session, reauth_on_401=True)
    assert norm.status == 200                                  # taze token ile geçti
    assert session.actor.auth.headers["Authorization"] == "Bearer NEW"
    await store.aclose_all()


async def test_default_does_not_reauth():
    """Opt-in kapalıyken 401 aynen döner (oracle semantiği korunur) — re-auth tetiklenmez."""
    called = {"n": 0}

    async def reauth():
        called["n"] += 1
        return AuthState(headers={"Authorization": "Bearer NEW"})

    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(lambda r: httpx.Response(401)))
    session = store.create(
        Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer OLD"})), reauth=reauth)
    norm = await Replayer(PolicyEngine(_scope())).replay(
        CapturedRequest(method="GET", url=f"{BASE}/api/x"), session)   # reauth_on_401 varsayılan False
    assert norm.status == 401 and called["n"] == 0
    await store.aclose_all()


async def test_reauth_attempted_only_once():
    """Kalıcı 401'de re-auth yalnızca BİR kez denenir (sonsuz döngü yok)."""
    called = {"n": 0}

    async def reauth():
        called["n"] += 1
        return AuthState(headers={"Authorization": "Bearer NEW"})

    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(lambda r: httpx.Response(401)))
    session = store.create(
        Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer OLD"})), reauth=reauth)
    norm = await Replayer(PolicyEngine(_scope())).replay(
        CapturedRequest(method="GET", url=f"{BASE}/api/x"), session, reauth_on_401=True)
    assert norm.status == 401 and called["n"] == 1
    await store.aclose_all()


async def test_refresh_auth_without_hook_is_false():
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    session = store.create(Actor(name="a", auth=AuthState()))   # reauth verilmedi
    assert await session.refresh_auth() is False
    await store.aclose_all()


async def test_refresh_auth_swallows_provider_error_and_keeps_old_state():
    async def bad():
        raise RuntimeError("login failed")

    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    session = store.create(
        Actor(name="a", auth=AuthState(headers={"Authorization": "Bearer OLD"})), reauth=bad)
    assert await session.refresh_auth() is False
    assert session.actor.auth.headers["Authorization"] == "Bearer OLD"   # eski state korunur
    await store.aclose_all()


async def test_refresh_auth_applies_new_cookies():
    async def reauth():
        return AuthState(cookies={"session": "fresh"})

    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    session = store.create(Actor(name="a", auth=AuthState(cookies={"session": "old"})), reauth=reauth)
    assert await session.refresh_auth() is True
    assert session.client.cookies.get("session") == "fresh"
    await store.aclose_all()
