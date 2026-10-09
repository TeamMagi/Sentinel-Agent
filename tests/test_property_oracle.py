"""Property-based (metamorfik) oracle değişmezleri (#7) — hypothesis ile fuzz.

Tezimizin matematiksel güvencesi: **leaked-marker olmadan asla CONFIRMED yok.** Rastgele üretilen
yüzlerce saldırgan-yanıtı için IdorOracle CONFIRMED derse, kanıt (sızan owner-private marker)
GERÇEKTEN saldırganın yanıt gövdesinde bulunmalı. Ağsız (httpx.MockTransport)."""
from __future__ import annotations

import asyncio

import httpx
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import IdorOracle
from pentestai.oracle.base import CONFIRMED
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"
# Kurbanın kendi (owner-private) verisi — benzersiz, tahmin edilemez marker'lar içerir.
VICTIM = {"id": "A-100", "email": "alice@owner.local", "secret": "OWNERPRIVATE_TOKEN_9x7Q"}
ATTACKER_OWN = {"id": "B-200", "email": "bob@owner.local"}
EP = Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id")


def _run(attacker_cross_body: dict):
    def handler(request):
        oid = request.url.path.rsplit("/", 1)[-1]
        tok = request.headers.get("authorization", "").replace("Bearer ", "")
        if tok == "TOKEN_A" and oid == "A-100":
            return httpx.Response(200, json=VICTIM)              # kurban kendi verisini okur
        if tok == "TOKEN_B" and oid == "B-200":
            return httpx.Response(200, json=ATTACKER_OWN)        # saldırgan kendi verisi (neg. kontrol)
        if tok == "TOKEN_B" and oid == "A-100":
            return httpx.Response(200, json=attacker_cross_body)  # ÇAPRAZ erişim — fuzz'lanan gövde
        return httpx.Response(404, json={"error": "nf"})

    async def _go():
        store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
        A = Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer TOKEN_A"}),
                  own_object_ids={"order": "A-100"})
        B = Actor(name="user_B", auth=AuthState(headers={"Authorization": "Bearer TOKEN_B"}),
                  own_object_ids={"order": "B-200"})
        oracle = IdorOracle(Replayer(PolicyEngine(
            Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"]))), BASE)
        try:
            return await oracle.run(EP, store.create(A), store.create(B), resource_key="order")
        finally:
            await store.aclose_all()

    return asyncio.run(_go())


# Rastgele saldırgan çapraz-erişim gövdesi: keyfi anahtar/değerler (marker sızması bazen olur, bazen olmaz).
_bodies = st.dictionaries(
    st.text(min_size=1, max_size=10),
    st.one_of(st.text(max_size=40), st.integers(), st.booleans(), st.none()),
    max_size=6,
)


@settings(max_examples=80, deadline=None)
@given(attacker_cross_body=_bodies)
def test_confirmed_implies_marker_actually_leaked(attacker_cross_body):
    f = _run(attacker_cross_body)
    if f.verdict == CONFIRMED:
        # DEĞİŞMEZ: CONFIRMED ise sızan marker kaydı boş olamaz ve gerçekten attack yanıtındadır.
        assert f.evidence.leaked_markers, "CONFIRMED ama leaked_marker yok — tez ihlali"
        body = (f.evidence.attack_response.body_text or "").lower() if f.evidence.attack_response else ""
        assert any(m.lower() in body for m in f.evidence.leaked_markers), \
            "CONFIRMED ama hiçbir marker attack yanıt gövdesinde değil — kanıtsız karar"


@settings(max_examples=60, deadline=None)
@given(noise=st.text(max_size=50))
def test_no_owner_private_leak_is_never_confirmed(noise):
    """Saldırgan çapraz yanıtı owner-private marker İÇERMEZSE (yalnız gürültü) asla CONFIRMED olmaz."""
    # hypothesis tesadüfen bir owner-private değeri üretmesin (üretirse sızıntı DOĞRU olurdu).
    assume(not any(v.lower() in noise.lower() for v in ("alice@owner.local", "OWNERPRIVATE_TOKEN_9x7Q")))
    body = {"status": "ok", "note": noise, "items": []}
    f = _run(body)
    assert f.verdict != CONFIRMED
