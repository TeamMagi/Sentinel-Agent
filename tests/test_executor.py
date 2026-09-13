"""ActionExecutor — tipli aksiyon icrası (Faz 1). DESIGN.md §10.9 (agentic çekirdek).

Network'süz (MockTransport). Doğrulananlar: Probe tekil istek gözlemi; RunOracle vulnerable
hedefte CONFIRMED; scope-dışı istekte crash değil açıklamalı Observation; bilinmeyen aksiyon/oracle
güvenli şekilde ele alınır. Executor ASLA verdict vermez — onu oracle (kod) verir.
"""
import httpx
import pytest

from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import IdorOracle
from pentestai.oracle import base
from pentestai.orchestrator.actions import Action, Probe, RunOracle
from pentestai.orchestrator.executor import ActionExecutor
from pentestai.policy import PolicyEngine

DB = {
    "A-100": {"id": "A-100", "email": "alice@test.local", "total": 42.5, "owner": "user_A"},
    "B-200": {"id": "B-200", "email": "bob@test.local", "total": 10.0, "owner": "user_B"},
}
TOKEN_ACTOR = {"TOKEN_A": "user_A", "TOKEN_B": "user_B"}
ENDPOINT = Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id")
BASE = "http://localhost:3000"


def _actor_of(request):
    return TOKEN_ACTOR.get(request.headers.get("authorization", "").replace("Bearer ", ""))


def vulnerable_handler(request):
    oid = request.url.path.rsplit("/", 1)[-1]
    if oid not in DB:
        return httpx.Response(404, json={"error": "not found"})
    return httpx.Response(200, json=DB[oid])          # ownership check YOK → IDOR


def _setup(*, allowed_prefixes=("/",)):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000],
                  allowed_path_prefixes=list(allowed_prefixes))
    store = SessionStore(transport=httpx.MockTransport(vulnerable_handler))
    replayer = Replayer(PolicyEngine(scope))
    A = Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer TOKEN_A"}),
              own_object_ids={"orders": "A-100"})
    B = Actor(name="user_B", auth=AuthState(headers={"Authorization": "Bearer TOKEN_B"}),
              own_object_ids={"orders": "B-200"})
    oracles = {"idor": IdorOracle(replayer, BASE)}
    executor = ActionExecutor(replayer, oracles, BASE)
    sessions = {"user_A": store.create(A), "user_B": store.create(B)}
    return store, executor, sessions


@pytest.mark.asyncio
async def test_probe_returns_observation():
    store, executor, sessions = _setup()
    obs = await executor.execute(
        Probe(endpoint=ENDPOINT, actor_name="user_A"), sessions)
    assert obs.action_type == "probe"
    assert obs.status == 200
    assert obs.finding is None          # Probe verdict üretmez
    await store.aclose_all()


@pytest.mark.asyncio
async def test_run_oracle_confirmed_on_vulnerable():
    store, executor, sessions = _setup()
    obs = await executor.execute(
        RunOracle(oracle="idor", endpoint=ENDPOINT,
                  victim_name="user_A", attacker_name="user_B", resource_key="orders"), sessions)
    assert obs.action_type == "run_oracle"
    assert obs.finding is not None
    assert obs.finding.verdict == base.CONFIRMED
    await store.aclose_all()


@pytest.mark.asyncio
async def test_scope_denial_is_clean_observation():
    # scope yalnızca /rest/* izinli → /api/orders policy'den reddedilir → crash değil, açıklama
    store, executor, sessions = _setup(allowed_prefixes=("/rest/",))
    obs = await executor.execute(Probe(endpoint=ENDPOINT, actor_name="user_A"), sessions)
    assert obs.status is None and "policy" in obs.note
    await store.aclose_all()


@pytest.mark.asyncio
async def test_unknown_oracle_is_handled():
    store, executor, sessions = _setup()
    obs = await executor.execute(
        RunOracle(oracle="yok", endpoint=ENDPOINT,
                  victim_name="user_A", attacker_name="user_B"), sessions)
    assert obs.finding is None and "bilinmeyen oracle" in obs.note
    await store.aclose_all()


@pytest.mark.asyncio
async def test_unknown_action_is_handled():
    store, executor, sessions = _setup()
    # Kaydı olmayan taban Action (kind="action") → güvenli şekilde reddedilir.
    obs = await executor.execute(Action(), sessions)
    assert "bilinmeyen aksiyon" in obs.note
    await store.aclose_all()


@pytest.mark.asyncio
async def test_missing_actor_is_handled():
    store, executor, sessions = _setup()
    obs = await executor.execute(Probe(endpoint=ENDPOINT, actor_name="hayalet"), sessions)
    assert obs.status is None and "aktör" in obs.note
    await store.aclose_all()
