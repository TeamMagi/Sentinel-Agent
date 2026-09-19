"""net/replay — cross-contamination guard. DESIGN.md §14 (en kritik test).

Bir aktörün auth'u başka aktörün isteğinde ASLA görünmemeli.
"""
import httpx
import pytest

from pentestai.models import Actor, AuthState, CapturedRequest, Scope
from pentestai.net.replay import Session, replay
from pentestai.net.session_store import build_client


def _scope():
    return Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])


@pytest.mark.asyncio
async def test_no_cross_contamination():
    captured: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request.headers.get("authorization"))
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)
    A = Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer TOKEN_A"}))
    B = Actor(name="user_B", auth=AuthState(headers={"Authorization": "Bearer TOKEN_B"}))
    sA = Session(A, build_client(A, transport=transport))
    sB = Session(B, build_client(B, transport=transport))

    # base, user_A'nın token'ıyla yakalanmış (kirli):
    base = CapturedRequest(
        method="GET", url="http://localhost:3000/api/orders/1",
        headers={"Authorization": "Bearer TOKEN_A"},
    )

    await replay(base, sB, _scope())      # B ile replay
    assert captured[-1] == "Bearer TOKEN_B"   # A sızmadı

    await replay(base, sA, _scope())      # A ile replay
    assert captured[-1] == "Bearer TOKEN_A"

    await sA.client.aclose()
    await sB.client.aclose()


@pytest.mark.asyncio
async def test_out_of_scope_raises():
    from pentestai.net.replay import ScopeError

    def handler(request):  # pragma: no cover - çağrılmamalı
        raise AssertionError("scope dışı istek gönderildi!")

    A = Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer T"}))
    sA = Session(A, build_client(A, transport=httpx.MockTransport(handler)))
    base = CapturedRequest(method="GET", url="http://evil.example:3000/x")
    with pytest.raises(ScopeError):
        await replay(base, sA, _scope())
    await sA.client.aclose()
