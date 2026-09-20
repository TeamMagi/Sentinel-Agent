"""LLMSelector + _parse_actions — structured-outputs + toleranslı parse.

Seçici LLM çıktısını çalıştırılabilir Action'lara çevirir; qwen3.8 gibi modeller için
format olarak JSON ŞEMA geçer ve dizi/wrapper/tek-nesne biçimlerini kabul eder.
"""
from types import SimpleNamespace

import pytest

from pentestai.llm.client import LLMClient
from pentestai.models import Endpoint
from pentestai.orchestrator.actions import Probe, RunOracle
from pentestai.orchestrator.selectors import (
    LLMSelector,
    _parse_actions,
    action_select_json_schema,
)


class _CaptureLLM(LLMClient):
    def __init__(self, completion: str):
        self.completion = completion
        self.fmt = None

    async def complete(self, system: str, user: str, *, fmt=None) -> str:
        self.fmt = fmt
        return self.completion


def _sessions():
    return {"user_A": SimpleNamespace(actor=SimpleNamespace(role="user", name="user_A")),
            "user_B": SimpleNamespace(actor=SimpleNamespace(role="admin", name="user_B"))}


RUN = ('{"action":"run_oracle","oracle":"idor","path_template":"/api/x/{id}",'
       '"victim_name":"user_A","attacker_name":"user_B","rationale":"r"}')
PROBE = '{"action":"probe","path_template":"/api/x/{id}","actor_name":"user_A","rationale":"r"}'


def test_parse_top_level_array():
    acts = _parse_actions(f"[{RUN}]")
    assert len(acts) == 1 and isinstance(acts[0], RunOracle)


def test_parse_wrapper_object():
    # Local modelin structured-outputs biçimi: {"actions":[...]}
    acts = _parse_actions(f'{{"actions":[{RUN},{PROBE}]}}')
    assert len(acts) == 2
    assert isinstance(acts[0], RunOracle) and isinstance(acts[1], Probe)


def test_parse_single_object():
    acts = _parse_actions(PROBE)
    assert len(acts) == 1 and isinstance(acts[0], Probe)


def test_parse_incomplete_action_dropped():
    # victim/attacker eksik run_oracle → to_action None → sessizce elenir (crash yok)
    assert _parse_actions('{"action":"run_oracle","oracle":"idor","path_template":"/api/x"}') == []


def test_parse_garbage_returns_empty():
    assert _parse_actions("üzgünüm, aksiyon yok") == []


def test_schema_shape():
    s = action_select_json_schema()
    assert s["properties"]["actions"]["type"] == "array"
    item = s["properties"]["actions"]["items"]
    # Faz 4 aksiyon tipleri şemada mevcut (ProposeAction ile hizalı)
    assert {"probe", "run_oracle", "enumerate_ids", "escalate_role"} <= set(item["properties"]["action"]["enum"])


@pytest.mark.asyncio
async def test_llm_selector_passes_schema_format():
    llm = _CaptureLLM('{"actions":[]}')
    sel = LLMSelector(llm)
    eps = [Endpoint(method="GET", path_template="/api/x/{id}")]
    world = SimpleNamespace(situation_report=lambda: "durum")
    await sel.next_actions(world, eps, _sessions())
    assert isinstance(llm.fmt, dict)
    assert "actions" in llm.fmt["properties"]


@pytest.mark.asyncio
async def test_llm_selector_respects_batch_limit():
    many = ",".join([RUN] * 5)
    llm = _CaptureLLM(f'{{"actions":[{many}]}}')
    sel = LLMSelector(llm, batch=2)
    world = SimpleNamespace(situation_report=lambda: "durum")
    acts = await sel.next_actions(world, [Endpoint(method="GET", path_template="/api/x/{id}")], _sessions())
    assert len(acts) == 2   # batch sınırı uygulanır
