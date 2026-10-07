"""Verifier + çok-geçişli doğrulama (Faz 5).

Flakiness'i deterministik kurmak için `ScriptedOracle` kullanılır (her run'da önceden yazılmış
verdict döner). Doğrulananlar: kararsızlık tespiti; kararlı bulgu korunur; state_change
tekrar-doğrulanamaz; orchestrator kararsız CONFIRMED'i INCONCLUSIVE'e düşürür (baraj yükselmez).
"""
import httpx
import pytest

from pentestai.llm.client import MockLLMClient
from pentestai.models import Actor, Endpoint, Evidence, Finding, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle.base import Oracle
from pentestai.orchestrator.actions import ReVerify
from pentestai.orchestrator.agent import AgenticOrchestrator
from pentestai.orchestrator.executor import ActionExecutor
from pentestai.orchestrator.verifier import Verifier
from pentestai.policy import PolicyEngine

EP = Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id")
BASE = "http://localhost:3000"
CANNED = ('[{"action":"run_oracle","oracle":"idor","method":"GET",'
          '"path_template":"/api/orders/{id}","resource_key":"orders",'
          '"victim_name":"user_A","attacker_name":"user_B","rationale":"t"}]')


class ScriptedOracle(Oracle):
    """Her run'da sıradaki verdict'i döner (flakiness'i deterministik taklit eder)."""

    vuln_type = "idor"

    def __init__(self, verdicts):
        self._verdicts = list(verdicts)
        self._i = 0

    async def run(self, endpoint, victim, attacker, *, resource_key="id", finding_id="F-001"):
        v = self._verdicts[min(self._i, len(self._verdicts) - 1)]
        self._i += 1
        markers = ["alice@x"] if v == "CONFIRMED" else []
        return Finding(id=finding_id, type="idor", endpoint=endpoint.path_template,
                       method=endpoint.method, verdict=v,
                       evidence=Evidence(leaked_markers=markers))


@pytest.mark.asyncio
async def test_verifier_detects_instability():
    v = Verifier({"idor": ScriptedOracle(["CONFIRMED", "REJECTED", "CONFIRMED"])})
    r = await v.reverify("idor", EP, None, None, resource_key="orders")
    assert r.reverifiable and not r.stable
    assert r.verdicts == ["CONFIRMED", "REJECTED", "CONFIRMED"]


@pytest.mark.asyncio
async def test_verifier_stable_finding_unchanged():
    v = Verifier({"idor": ScriptedOracle(["CONFIRMED"] * 5)})
    r = await v.reverify("idor", EP, None, None)
    assert r.stable and r.verdicts == ["CONFIRMED", "CONFIRMED", "CONFIRMED"]


@pytest.mark.asyncio
async def test_state_change_not_reverifiable():
    v = Verifier({"state_change_authz": ScriptedOracle(["CONFIRMED"])})
    r = await v.reverify("state_change_authz", EP, None, None)
    assert not r.reverifiable and r.verdicts == []


def _orchestrator(script):
    store = SessionStore(transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    executor = ActionExecutor(Replayer(PolicyEngine(scope)), {"idor": ScriptedOracle(script)}, BASE)
    A = Actor(name="user_A", own_object_ids={"orders": "A-100"})
    B = Actor(name="user_B", own_object_ids={"orders": "B-200"})
    sessions = {"user_A": store.create(A), "user_B": store.create(B)}
    agent = AgenticOrchestrator(executor, [EP], llm=MockLLMClient(completion=CANNED),
                                base_url=BASE, max_iterations=5)
    return store, agent, sessions


@pytest.mark.asyncio
async def test_orchestrator_demotes_flaky_confirmed():
    # main loop: CONFIRMED → reverify: [CONFIRMED, REJECTED, CONFIRMED] kararsız → INCONCLUSIVE'e düş
    store, agent, sessions = _orchestrator(["CONFIRMED", "CONFIRMED", "REJECTED", "CONFIRMED"])
    state = await agent.run(sessions)
    assert state.findings and state.findings[0].verdict == "INCONCLUSIVE"
    await store.aclose_all()


@pytest.mark.asyncio
async def test_orchestrator_keeps_stable_confirmed():
    store, agent, sessions = _orchestrator(["CONFIRMED"] * 4)
    state = await agent.run(sessions)
    assert state.findings[0].verdict == "CONFIRMED"
    await store.aclose_all()


@pytest.mark.asyncio
async def test_reverify_action_via_executor():
    store = SessionStore(transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    executor = ActionExecutor(Replayer(PolicyEngine(scope)),
                              {"idor": ScriptedOracle(["CONFIRMED", "REJECTED"])}, BASE)
    sessions = {"user_A": store.create(Actor(name="user_A")),
                "user_B": store.create(Actor(name="user_B"))}
    obs = await executor.execute(
        ReVerify(oracle="idor", endpoint=EP, victim_name="user_A",
                 attacker_name="user_B", resource_key="orders", runs=2), sessions)
    assert obs.action_type == "reverify" and "stable=False" in obs.note
    await store.aclose_all()
