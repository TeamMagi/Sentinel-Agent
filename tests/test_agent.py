"""AgenticOrchestrator — reasoning döngüsü (Faz 3). DESIGN.md §10.9.

Network'süz (MockTransport). Doğrulananlar:
  • Deterministik mod (LLM'siz) vulnerable hedefte CONFIRMED üretir + iz (trace) dolu.
  • Scope-dışı LLM önerisi ağa çıkmaz / CONFIRMED üretmez (değişmez 1 & 2).
  • Bütçe kill-switch döngüyü durdurur.
"""
import httpx
import pytest

from pentestai.llm.client import MockLLMClient
from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import BudgetTracker, Replayer, SessionStore
from pentestai.oracle import BflaOracle, BoplaOracle, IdorOracle, InjectionOracle, StateChangingOracle
from pentestai.orchestrator.agent import AgenticOrchestrator
from pentestai.policy import PolicyEngine

DB = {
    "A-100": {"id": "A-100", "email": "alice@test.local", "total": 42.5, "owner": "user_A"},
    "B-200": {"id": "B-200", "email": "bob@test.local", "total": 10.0, "owner": "user_B"},
}
TOKEN_ACTOR = {"TOKEN_A": "user_A", "TOKEN_B": "user_B"}
ENDPOINT = Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id")
BASE = "http://localhost:3000"


def vulnerable_handler(request):
    oid = request.url.path.rsplit("/", 1)[-1]
    if oid not in DB:
        return httpx.Response(404, json={"error": "not found"})
    return httpx.Response(200, json=DB[oid])          # ownership check YOK → IDOR


def _oracles(replayer):
    return {
        "idor": IdorOracle(replayer, BASE), "bfla": BflaOracle(replayer, BASE),
        "excessive_data_exposure": BoplaOracle(replayer, BASE),
        "injection": InjectionOracle(replayer, BASE),
        "state_change_authz": StateChangingOracle(replayer, BASE),
    }


def _setup(*, budget=None, allowed_prefixes=("/",)):
    from pentestai.orchestrator.executor import ActionExecutor
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000],
                  allowed_path_prefixes=list(allowed_prefixes))
    store = SessionStore(transport=httpx.MockTransport(vulnerable_handler))
    replayer = Replayer(PolicyEngine(scope), budget=budget)
    executor = ActionExecutor(replayer, _oracles(replayer), BASE)
    A = Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer TOKEN_A"}),
              own_object_ids={"orders": "A-100"})
    B = Actor(name="user_B", auth=AuthState(headers={"Authorization": "Bearer TOKEN_B"}),
              own_object_ids={"orders": "B-200"})
    sessions = {"user_A": store.create(A), "user_B": store.create(B)}
    return store, executor, sessions


@pytest.mark.asyncio
async def test_deterministic_loop_finds_idor():
    store, executor, sessions = _setup()
    agent = AgenticOrchestrator(executor, [ENDPOINT], llm=None, base_url=BASE, max_iterations=30)
    state = await agent.run(sessions)
    assert any(f.verdict == "CONFIRMED" and f.type == "idor" for f in state.findings)
    assert agent.trace.steps                    # iz dolduruldu
    assert any(s.verdict_delta and "CONFIRMED" in s.verdict_delta for s in agent.trace.steps)
    await store.aclose_all()


@pytest.mark.asyncio
async def test_llm_out_of_scope_proposal_is_safe():
    # LLM kapsam-dışı bir path önerir; policy reddeder → CONFIRMED üretilmez, crash yok.
    canned = ('[{"action":"run_oracle","oracle":"idor","method":"GET",'
              '"path_template":"/evil/{id}","resource_key":"evil",'
              '"victim_name":"user_A","attacker_name":"user_B","rationale":"deneme"}]')
    store, executor, sessions = _setup(allowed_prefixes=("/api/",))
    agent = AgenticOrchestrator(executor, [ENDPOINT], llm=MockLLMClient(completion=canned),
                                base_url=BASE, max_iterations=5)
    state = await agent.run(sessions)
    assert not any(f.verdict == "CONFIRMED" for f in state.findings)
    await store.aclose_all()


@pytest.mark.asyncio
async def test_budget_kill_switch_stops_loop():
    store, executor, sessions = _setup(budget=BudgetTracker(max_total_requests=1))
    agent = AgenticOrchestrator(executor, [ENDPOINT], llm=None, base_url=BASE, max_iterations=30)
    state = await agent.run(sessions)          # BudgetExceeded döngüyü durdurur, patlamaz
    assert state is not None
    assert any(s.observation == "BUDGET_EXCEEDED" for s in agent.trace.steps)
    await store.aclose_all()
