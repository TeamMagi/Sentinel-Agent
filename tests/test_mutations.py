"""Faz 4 — ActionExecutor mutasyon/recon stratejileri + saf id yardımcıları.

Network'süz: genişletilmiş sahte app httpx.MockTransport ile sunulur.
Sahte app:
- /api/orders/{n}  → n ∈ {1,2,3} 200 (sıralı int id), gövdesinde addressId/productId/link
- /api/docs/{b64}  → base64(int) id uzayı; int ∈ {1,2} 200 (format mutasyonu için)
- /admin/stats     → herkese 200 (kırık fonksiyon yetkisi → BFLA CONFIRMED)
- /admin/config    → yalnız admin 200, düşük yetkili 403 (yetki sağlam → BFLA REJECTED)
"""
import base64
import re

import httpx
import pytest

from pentestai.models import Actor, AuthState, Endpoint, Finding, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import BflaOracle, IdorOracle
from pentestai.oracle.base import CONFIRMED, Oracle
from pentestai.orchestrator import (
    ActionExecutor,
    EnumerateIds,
    EscalateRole,
    InspectResponseForIds,
    MutateIdFormat,
    Probe,
    RunOracle,
)
from pentestai.orchestrator.idtools import (
    detect_id_format,
    extract_ids_from_body,
    id_format_variants,
)
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"
ORDERS = {"1", "2", "3"}
DOCS_INTS = {1, 2}


def _app(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    m = re.match(r"^/api/orders/(\d+)$", path)
    if m:
        oid = m.group(1)
        if oid in ORDERS:
            return httpx.Response(200, json={
                "id": int(oid), "addressId": 42, "items": [{"productId": 7}],
                "self": f"/api/orders/{oid}", "next": f"/api/orders/{int(oid) + 1}",
            })
        return httpx.Response(404, json={"error": "not found"})
    if path == "/api/orders":
        return httpx.Response(200, json=[{"id": 1}])
    m = re.match(r"^/api/docs/([^/]+)$", path)
    if m:
        try:
            n = int(base64.b64decode(m.group(1), validate=True).decode())
        except Exception:
            return httpx.Response(404, json={"error": "bad id"})
        return httpx.Response(200, json={"id": m.group(1)}) if n in DOCS_INTS \
            else httpx.Response(404, json={"error": "not found"})
    if path == "/admin/stats":
        return httpx.Response(200, json={"count": 5})                  # kırık: herkese açık
    if path == "/admin/config":
        auth = request.headers.get("authorization", "")
        return httpx.Response(200, json={"flag": "x", "secret": "y"}) if "ADMIN" in auth \
            else httpx.Response(403, json={"error": "forbidden"})
    return httpx.Response(404, json={"error": "unknown"})


def _env(*, path_prefixes=None, oracles=None):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000],
                  allowed_path_prefixes=path_prefixes or ["/"])
    replayer = Replayer(PolicyEngine(scope))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(_app))
    actors = [
        Actor(name="alice", role="user", auth=AuthState(headers={"Authorization": "Bearer ALICE"})),
        Actor(name="mallory", role="user", auth=AuthState(headers={"Authorization": "Bearer MALLORY"})),
        Actor(name="admin", role="admin", auth=AuthState(headers={"Authorization": "Bearer ADMIN"})),
    ]
    sessions = {a.name: store.create(a) for a in actors}
    if oracles is None:
        oracles = {"idor": IdorOracle(replayer, BASE), "bfla": BflaOracle(replayer, BASE)}
    return ActionExecutor(replayer, oracles, BASE), sessions


# --- saf id yardımcıları -----------------------------------------------------

def test_detect_id_format():
    assert detect_id_format("42") == "int"
    assert detect_id_format(base64.b64encode(b"7").decode()) == "base64-int"
    assert detect_id_format("550e8400-e29b-41d4-a716-446655440000") == "uuid"
    assert detect_id_format("abc$xyz") == "opaque"


def test_id_format_variants_int_and_base64():
    assert id_format_variants("1") == ["MQ==", "Mg==", "2"]          # int → b64(1), b64(2), 2
    assert id_format_variants("MQ==") == ["1", "2", "Mg=="]           # b64(1) → 1, 2, b64(2)
    assert id_format_variants("550e8400-e29b-41d4-a716-446655440000") == []  # uuid: sıralı değil


def test_extract_ids_from_body_keys_and_links():
    body = {"id": 1, "addressId": 42, "items": [{"productId": 7}],
            "self": "/api/orders/1", "next": "/api/orders/2", "valid": True}
    ids = set(extract_ids_from_body(body))
    assert {"1", "42", "7", "2"} <= ids
    assert "True" not in ids                                          # bool id sayılmaz
    # "valid" düz "...id" ile bittiği için anahtar olarak alınmaz (false-positive tuzağı yok)


# --- EnumerateIds ------------------------------------------------------------

@pytest.mark.asyncio
async def test_enumerate_ids_finds_sequential_neighbors():
    ex, sessions = _env()
    ep = Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id")
    obs = await ex.execute(
        EnumerateIds(endpoint=ep, actor_name="alice", around_id="1", span=3), sessions)
    assert obs.action_type == "enumerate_ids"
    assert set(obs.discovered_ids) == {"2", "3"}      # 1 hariç, 4 → 404
    assert obs.finding is None                          # keşif verdict vermez


@pytest.mark.asyncio
async def test_enumerate_ids_non_int_is_noop():
    ex, sessions = _env()
    ep = Endpoint(path_template="/api/docs/{id}", id_param="id")
    obs = await ex.execute(
        EnumerateIds(endpoint=ep, actor_name="alice", around_id="MQ==", span=2), sessions)
    assert obs.discovered_ids == []
    assert "tam sayı değil" in obs.note


# --- MutateIdFormat ----------------------------------------------------------

@pytest.mark.asyncio
async def test_mutate_id_format_base64_decode_increment_encode():
    ex, sessions = _env()
    ep = Endpoint(path_template="/api/docs/{id}", id_param="id")
    b64_one = base64.b64encode(b"1").decode()          # "MQ=="
    obs = await ex.execute(
        MutateIdFormat(endpoint=ep, actor_name="alice", base_id=b64_one), sessions)
    assert "Mg==" in obs.discovered_ids                 # base64(1)→decode→+1→encode base64(2)


@pytest.mark.asyncio
async def test_mutate_id_format_int_to_base64():
    ex, sessions = _env()
    ep = Endpoint(path_template="/api/docs/{id}", id_param="id")
    obs = await ex.execute(
        MutateIdFormat(endpoint=ep, actor_name="alice", base_id="1"), sessions)
    assert "MQ==" in obs.discovered_ids and "Mg==" in obs.discovered_ids


# --- InspectResponseForIds ---------------------------------------------------

@pytest.mark.asyncio
async def test_inspect_response_for_ids_from_prior_observation():
    ex, sessions = _env()
    await ex.execute(Probe(endpoint=Endpoint(path_template="/api/orders/1"),
                           actor_name="alice"), sessions)
    obs = await ex.execute(InspectResponseForIds(source_note="order 1"), sessions)
    ids = set(obs.discovered_ids)
    assert {"42", "7", "2"} <= ids                      # addressId, productId, next-link path id


@pytest.mark.asyncio
async def test_inspect_without_prior_observation_is_clean():
    ex, sessions = _env()
    obs = await ex.execute(InspectResponseForIds(), sessions)
    assert obs.discovered_ids == []
    assert "önceki gözlem yok" in obs.note


# --- EscalateRole (BFLA) -----------------------------------------------------

@pytest.mark.asyncio
async def test_escalate_role_confirmed_on_broken_authz():
    ex, sessions = _env()
    ep = Endpoint(method="GET", path_template="/admin/stats")
    obs = await ex.execute(EscalateRole(endpoint=ep, low_actor_name="mallory"), sessions)
    assert obs.finding is not None and obs.finding.verdict == "CONFIRMED"


@pytest.mark.asyncio
async def test_escalate_role_rejected_when_authz_holds():
    ex, sessions = _env()
    ep = Endpoint(method="GET", path_template="/admin/config")
    obs = await ex.execute(EscalateRole(endpoint=ep, low_actor_name="mallory"), sessions)
    assert obs.finding is not None and obs.finding.verdict == "REJECTED"


# --- RunOracle: verdict oracle'a ait (kural 2) -------------------------------

class _StubOracle(Oracle):
    vuln_type = "idor"

    async def run(self, endpoint, victim, attacker, *, resource_key="id", finding_id="F-001"):
        return Finding(id=finding_id, type="idor", endpoint=endpoint.path_template,
                       verdict=CONFIRMED, confidence="high")


@pytest.mark.asyncio
async def test_run_oracle_delegates_verdict():
    ep = Endpoint(path_template="/api/orders/{id}", id_param="id")
    # Stub oracle ağ kullanmaz (replayer=None); executor onun verdict'ini olduğu gibi taşır.
    ex, sessions = _env(oracles={"idor": _StubOracle(None, BASE)})
    obs = await ex.execute(
        RunOracle(oracle="idor", endpoint=ep, victim_name="alice",
                  attacker_name="mallory", resource_key="orders"), sessions)
    assert obs.action_type == "run_oracle"
    assert obs.finding is not None and obs.finding.verdict == "CONFIRMED"


# --- Policy reddi temiz gözleme çevrilir (kural 5, crash yok) ----------------

@pytest.mark.asyncio
async def test_scope_denied_returns_clean_observation():
    ex, sessions = _env(path_prefixes=["/api/"])        # /admin kapsam dışı
    obs = await ex.execute(Probe(endpoint=Endpoint(path_template="/admin/config"),
                                 actor_name="alice"), sessions)
    assert obs.finding is None
    assert "policy" in obs.note.lower()


@pytest.mark.asyncio
async def test_enumerate_all_denied_is_clean():
    ex, sessions = _env(path_prefixes=["/nope/"])        # her şey kapsam dışı
    ep = Endpoint(path_template="/api/orders/{id}", id_param="id")
    obs = await ex.execute(
        EnumerateIds(endpoint=ep, actor_name="alice", around_id="1", span=3), sessions)
    assert obs.discovered_ids == []                      # hepsi reddedildi, çökme yok


# --- Kabul kriteri: aksiyon dizisi kapsamı genişletir ------------------------

@pytest.mark.asyncio
async def test_action_sequence_expands_discovery():
    ex, sessions = _env()
    orders = Endpoint(path_template="/api/orders/{id}", id_param="id")
    await ex.execute(Probe(endpoint=Endpoint(path_template="/api/orders/1"),
                           actor_name="alice"), sessions)   # tek objeden başla
    inspected = await ex.execute(InspectResponseForIds(source_note="ilk"), sessions)
    enumerated = await ex.execute(
        EnumerateIds(endpoint=orders, actor_name="alice", around_id="1", span=3), sessions)
    total = set(inspected.discovered_ids) | set(enumerated.discovered_ids)
    assert {"2", "3"} <= total                            # tek objeden çok hedefe
    assert len(total) >= 3
