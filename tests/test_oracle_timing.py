"""TimingOracle (B2) — zamanlama-tabanlı kör SQLi + command injection.

Sahte saat (FakeClock) enjekte edilir: MockTransport handler'ı payload "uyut" içeriyorsa
saati istenen gecikme kadar ilerletir. Böylece gerçek sleep olmadan zamanlama differential'i
deterministik test edilir. Kanıt gecikmeyi kod tarafında ölçmektir.
"""
import re
from urllib.parse import unquote

import httpx
import pytest

from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import base
from pentestai.oracle.timing import TimingOracle
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"
ENDPOINT = Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id")


class FakeClock:
    """timer() çağrıları arasında handler'ın ayarladığı `pending` gecikmeyi tüketen sahte saat."""

    def __init__(self):
        self.t = 0.0
        self.pending = 0.0

    def __call__(self) -> float:
        self.t += self.pending
        self.pending = 0.0
        return self.t


def _requested_delay(raw: str) -> float:
    """Payload'daki 'uyut' gecikmesini (saniye) çıkar — doz-yanıt testinin çekirdeği.
    SLEEP(n)/pg_sleep(n)/sleep n · WAITFOR DELAY '0:0:n' · ping -n (n → n-1 saniye)."""
    raw = unquote(raw).lower()
    m = re.search(r"ping\s+-n\s+(\d+)", raw)
    if m:
        return float(int(m.group(1)) - 1)
    m = re.search(r"0:0:(\d+)", raw)
    if m:
        return float(m.group(1))
    m = re.search(r"sleep[\s(]+?(\d+)", raw)
    if m:
        return float(m.group(1))
    return 0.0


def _make_handler(clock: FakeClock, *, sleepy: bool, scale: bool = True):
    """`sleepy`: payload 'uyut' içerince gecikme uygula. `scale`: gerçek zafiyet gibi istenen
    dozla ORANTILI gecikme (True) mi, yoksa jitter/sabit-yavaşlık gibi doza bakmaksızın SABİT
    gecikme (False) mi üretilsin. scale=False → doz-yanıt doğrulaması CONFIRMED VERMEMELİ."""
    def handler(request):
        raw = str(request.url).lower()
        if sleepy and ("sleep" in raw or "pg_sleep" in raw or "waitfor" in raw or "ping" in raw):
            clock.pending = _requested_delay(raw) if scale else 3.0
        return httpx.Response(200, json={"id": "1"})
    return handler


def _setup(handler, clock):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    s = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer A"})))
    oracle = TimingOracle(Replayer(PolicyEngine(scope)), BASE,
                          timer=clock, samples=2, delay_sec=3)
    return store, oracle, s


@pytest.mark.asyncio
async def test_blind_sqli_confirmed_on_delay():
    clock = FakeClock()
    store, oracle, s = _setup(_make_handler(clock, sleepy=True), clock)
    fs = await oracle.test_param(ENDPOINT, s, param="id", location="path")
    await store.aclose_all()
    sqli = next(f for f in fs if f.type == "blind_sqli")
    assert sqli.verdict == base.CONFIRMED
    assert sqli.evidence.leaked_markers          # gecikme imzası
    assert sqli.evidence.negative_control is True  # benign hızlıydı


@pytest.mark.asyncio
async def test_command_injection_confirmed_on_delay():
    clock = FakeClock()
    store, oracle, s = _setup(_make_handler(clock, sleepy=True), clock)
    fs = await oracle.test_param(ENDPOINT, s, param="id", location="path")
    await store.aclose_all()
    cmd = next(f for f in fs if f.type == "command_injection")
    assert cmd.verdict == base.CONFIRMED


@pytest.mark.asyncio
async def test_rejected_when_no_delay():
    clock = FakeClock()
    store, oracle, s = _setup(_make_handler(clock, sleepy=False), clock)
    fs = await oracle.test_param(ENDPOINT, s, param="id", location="path")
    await store.aclose_all()
    assert all(f.verdict == base.REJECTED for f in fs)   # gecikme yok → red


@pytest.mark.asyncio
async def test_inconclusive_when_delay_does_not_scale():
    """P1-FP regresyonu: payload'a bakmaksızın SABİT gecikme (jitter/yavaş endpoint) —
    düşük dozda eşiği aşsa bile yüksek dozla ORANTILI büyümediği için CONFIRMED VERİLMEZ."""
    clock = FakeClock()
    store, oracle, s = _setup(_make_handler(clock, sleepy=True, scale=False), clock)
    fs = await oracle.test_param(ENDPOINT, s, param="id", location="path")
    await store.aclose_all()
    assert all(f.verdict == base.INCONCLUSIVE for f in fs)   # ölçeklenmeyen gecikme → yanlış CONFIRMED yok
    assert all(f.verdict != base.CONFIRMED for f in fs)
