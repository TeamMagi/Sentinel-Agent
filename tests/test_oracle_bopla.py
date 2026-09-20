"""BoplaOracle — excessive data exposure. DESIGN.md §14.

Kanıt = cevapta dolu hassas alan. Gizlilik: yalnızca alan ADI saklanır, DEĞER değil.
"""
import httpx
import pytest

from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import base
from pentestai.oracle.bopla import BoplaOracle, SensitiveFieldScanner
from pentestai.policy import PolicyEngine

ENDPOINT = Endpoint(method="GET", path_template="/api/users/{id}", id_param="id")
BASE = "http://localhost:3000"
SECRET = "$2a$10$SECRETHASHVALUE"


def _handler(body):
    def h(request):
        return httpx.Response(200, json=body)
    return h


def _setup(body):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(_handler(body)))
    a = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer A"}),
                           own_object_ids={"users": "U1"}))
    return store, BoplaOracle(Replayer(PolicyEngine(scope)), BASE), a


@pytest.mark.asyncio
async def test_confirmed_on_hard_secret():
    body = {"id": "U1", "email": "a@x.local", "passwordHash": SECRET, "role": "user"}
    store, oracle, a = _setup(body)
    f = await oracle.run(ENDPOINT, a, a, resource_key="users")
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert "passwordHash" in f.evidence.leaked_markers      # alan adı
    assert "role" in f.evidence.leaked_markers               # soft alan da eklenir
    assert all(SECRET not in m for m in f.evidence.leaked_markers)  # DEĞER sızmaz
    await store.aclose_all()


@pytest.mark.asyncio
async def test_likely_on_soft_field_only():
    store, oracle, a = _setup({"id": "U1", "email": "a@x.local", "role": "admin"})
    f = await oracle.run(ENDPOINT, a, a, resource_key="users")
    assert f.verdict == base.LIKELY and f.evidence.leaked_markers == ["role"]
    await store.aclose_all()


@pytest.mark.asyncio
async def test_rejected_when_no_sensitive_field():
    store, oracle, a = _setup({"id": "U1", "email": "a@x.local", "name": "Bob"})
    f = await oracle.run(ENDPOINT, a, a, resource_key="users")
    assert f.verdict == base.REJECTED
    await store.aclose_all()


def test_scanner_ignores_empty_values():
    hard, soft = SensitiveFieldScanner().scan({"password": "", "apiKey": None, "token": "abc"})
    assert hard == set()          # boş/None değerli hassas alanlar sayılmaz
    assert soft == {"token"}       # dolu token → soft


def test_scanner_downgrades_substring_match_with_non_secret_value():
    # kod-tarama-raporu.md #3: "password" substring'i eşleşen ama DEĞERİ sır olmayan alanlar
    # (bool bayrak, ISO tarih damgası) hard/CONFIRMED değil, soft/LIKELY sayılmalı.
    hard, soft = SensitiveFieldScanner().scan({
        "passwordChangedAt": "2026-09-16T10:00:00Z",
        "passwordResetEnabled": True,
        "hasPassword": False,
    })
    assert hard == set()
    assert soft == {"passwordChangedAt", "passwordResetEnabled", "hasPassword"}


def test_scanner_keeps_exact_match_hard_regardless_of_value_shape():
    hard, soft = SensitiveFieldScanner().scan({"password": "hunter2"})
    assert hard == {"password"}
    assert soft == set()
