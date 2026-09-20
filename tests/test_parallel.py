"""ParallelOrchestrator — güvenli paralellik (Faz 6). DESIGN.md §10.9.

Network'süz (MockTransport), çok-endpoint'li vulnerable hedef. Doğrulananlar:
  • Doğruluk paritesi: paralel, sıralıyla AYNI CONFIRMED kümesini bulur (yol farklı, sonuç aynı).
  • Global bütçe: N scout tek BudgetTracker'ı paylaşır → toplam istek max'ı aşmaz (kill-switch global).
"""
import httpx
import pytest

from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import BudgetTracker, Replayer, SessionStore
from pentestai.oracle import BflaOracle, BoplaOracle, IdorOracle, InjectionOracle, StateChangingOracle
from pentestai.orchestrator.agent import AgenticOrchestrator
from pentestai.orchestrator.executor import ActionExecutor
from pentestai.orchestrator.parallel import ParallelOrchestrator
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"
COLLECTIONS = ("orders", "invoices", "tickets")
DBS = {
    c: {
        f"A-{c}": {"id": f"A-{c}", "email": f"a-{c}@test.local", "owner": "user_A"},
        f"B-{c}": {"id": f"B-{c}", "email": f"b-{c}@test.local", "owner": "user_B"},
    } for c in COLLECTIONS
}
ENDPOINTS = [Endpoint(method="GET", path_template=f"/api/{c}/{{id}}", id_param="id")
             for c in COLLECTIONS]


def vulnerable_handler(request):
    parts = request.url.path.strip("/").split("/")     # ["api","orders","A-orders"]
    coll, oid = parts[-2], parts[-1]
    db = DBS.get(coll, {})
    if oid not in db:
        return httpx.Response(404, json={"error": "not found"})
    return httpx.Response(200, json=db[oid])           # ownership check YOK → IDOR


def _oracles(replayer):
    return {
        "idor": IdorOracle(replayer, BASE), "bfla": BflaOracle(replayer, BASE),
        "excessive_data_exposure": BoplaOracle(replayer, BASE),
        "injection": InjectionOracle(replayer, BASE),
        "state_change_authz": StateChangingOracle(replayer, BASE),
    }


def _setup(*, budget=None):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(transport=httpx.MockTransport(vulnerable_handler))
    replayer = Replayer(PolicyEngine(scope), budget=budget)
    executor = ActionExecutor(replayer, _oracles(replayer), BASE)
    A = Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer TOKEN_A"}),
              own_object_ids={c: f"A-{c}" for c in COLLECTIONS})
    B = Actor(name="user_B", auth=AuthState(headers={"Authorization": "Bearer TOKEN_B"}),
              own_object_ids={c: f"B-{c}" for c in COLLECTIONS})
    sessions = {"user_A": store.create(A), "user_B": store.create(B)}
    return store, executor, sessions


def _confirmed_idor(findings):
    return {f.endpoint for f in findings if f.verdict == "CONFIRMED" and f.type == "idor"}


@pytest.mark.asyncio
async def test_parallel_matches_sequential():
    store1, ex1, s1 = _setup()
    seq = await AgenticOrchestrator(ex1, ENDPOINTS, llm=None, base_url=BASE).run(s1)

    store2, ex2, s2 = _setup()
    par = await ParallelOrchestrator(ex2, ENDPOINTS, llm=None, base_url=BASE, scouts=3).run(s2)

    assert _confirmed_idor(seq.findings) == _confirmed_idor(par.findings)
    assert len(_confirmed_idor(par.findings)) == len(COLLECTIONS)   # her endpoint'te bir IDOR
    await store1.aclose_all()
    await store2.aclose_all()


@pytest.mark.asyncio
async def test_shared_budget_is_global():
    budget = BudgetTracker(max_total_requests=5)
    store, executor, sessions = _setup(budget=budget)
    await ParallelOrchestrator(executor, ENDPOINTS, llm=None, base_url=BASE, scouts=3).run(sessions)
    # 3 scout tek bütçeyi paylaşır → toplam istek asla max'ı aşmaz (global kill-switch)
    assert budget.total <= 5
    await store.aclose_all()
