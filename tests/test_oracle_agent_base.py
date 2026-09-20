"""AgentOracle — scope kapısı ajan trace'lerinde de zorlanıyor mu (AS-1). DESIGN.md §10.6.

Ağsız: PolicyEngine gerçek, ama hiçbir HTTP isteği gitmiyor (yalnızca authorize() saf karar).
"""
import logging

import pytest

from pentestai.models import AgentTrace, Finding, Scope, ToolCall
from pentestai.oracle.agent_base import AgentOracle
from pentestai.policy import PolicyEngine


class _DummyAgentOracle(AgentOracle):
    vuln_type = "dummy_agent"

    async def run(self, trace: AgentTrace, *, finding_id: str = "F-001") -> Finding:
        in_scope, rejected = self._in_scope_calls(trace)
        self.last_in_scope = in_scope
        self.last_rejected = rejected
        return Finding(id=finding_id, type=self.vuln_type, endpoint="agent_trace",
                       verdict="REJECTED")


def _policy(*, destructive_tests=True, hosts=("agent.local",)):
    scope = Scope(allowed_hosts=list(hosts), allowed_ports=[443], allowed_path_prefixes=["/"],
                  allowed_methods=["GET", "POST"], destructive_tests=destructive_tests)
    return PolicyEngine(scope)


@pytest.mark.asyncio
async def test_call_without_target_url_is_always_in_scope():
    oracle = _DummyAgentOracle(_policy())
    trace = AgentTrace(calls=[ToolCall(name="fs.write", args={}, turn=0)])
    await oracle.run(trace)
    assert len(oracle.last_in_scope) == 1
    assert oracle.last_rejected == []


@pytest.mark.asyncio
async def test_call_with_in_scope_target_url_is_kept():
    oracle = _DummyAgentOracle(_policy())
    trace = AgentTrace(calls=[
        ToolCall(name="http.post", args={}, target_url="https://agent.local/webhook", turn=0),
    ])
    await oracle.run(trace)
    assert len(oracle.last_in_scope) == 1
    assert oracle.last_rejected == []


@pytest.mark.asyncio
async def test_out_of_scope_target_url_is_rejected_and_logged(caplog):
    oracle = _DummyAgentOracle(_policy(hosts=("agent.local",)))
    trace = AgentTrace(calls=[
        ToolCall(name="http.post", args={}, target_url="https://evil.example/exfil", turn=0),
    ])
    with caplog.at_level(logging.WARNING):
        await oracle.run(trace)
    assert oracle.last_in_scope == []
    assert len(oracle.last_rejected) == 1
    assert "scope dışı" in caplog.text


@pytest.mark.asyncio
async def test_destructive_disabled_rejects_network_tool_calls():
    # http.post ağa çıkan (POST, safe-method değil) bir aksiyon → destructive_tests=False iken
    # scope kapısı reddeder (§5.6 — LLM/ajan çıktısına güvenilmez).
    oracle = _DummyAgentOracle(_policy(destructive_tests=False))
    trace = AgentTrace(calls=[
        ToolCall(name="http.post", args={}, target_url="https://agent.local/webhook", turn=0),
    ])
    await oracle.run(trace)
    assert oracle.last_in_scope == []
    assert len(oracle.last_rejected) == 1
