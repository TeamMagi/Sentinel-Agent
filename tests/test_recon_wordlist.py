"""WordlistRecon (B5) — differential endpoint enümerasyonu.

Sahte hedef bilinen path'lere 200/401, bilinmeyene (bogus dahil) 404 döner. Keşif,
baseline (bogus 404) ile differential yaparak var olan endpoint'leri bulur. Network yok.
"""
import httpx
import pytest

from pentestai.models import Actor, AuthState, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.policy import PolicyEngine
from pentestai.recon.wordlist import WordlistRecon

BASE = "http://localhost:3000"


def handler(request):
    path = request.url.path
    if path == "/api/users":
        return httpx.Response(200, json=[{"id": 1}, {"id": 2}])
    if path == "/api/admin":
        return httpx.Response(401, json={"error": "unauthorized"})
    return httpx.Response(404, json={"error": "not found"})


@pytest.mark.asyncio
async def test_enumerate_discovers_existing_endpoints():
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    s = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer A"})))
    recon = WordlistRecon(Replayer(PolicyEngine(scope)), BASE,
                          wordlist=("users", "admin", "nonexistent"), prefixes=("/api/",))
    eps = await recon.enumerate(s)
    await store.aclose_all()
    paths = {e.path_template for e in eps}
    assert "/api/users" in paths      # 200 ≠ 404 → keşfedildi
    assert "/api/admin" in paths      # 401 ≠ 404 → keşfedildi (var ama korumalı)
    assert "/api/nonexistent" not in paths   # 404 → yok
