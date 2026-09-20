"""LLMSelector + _parse_actions — structured-outputs + toleranslı parse.

Seçici LLM çıktısını çalıştırılabilir Action'lara çevirir; qwen3.8 gibi modeller için
format olarak JSON ŞEMA geçer ve dizi/wrapper/tek-nesne biçimlerini kabul eder.
"""
from types import SimpleNamespace

import pytest

from pentestai.llm.client import LLMClient
from pentestai.models import Endpoint
from pentestai.orchestrator.actions import (
    EnumerateIds,
    EscalateRole,
    InspectResponseForIds,
    MutateIdFormat,
    Probe,
    RunOracle,
)
from pentestai.orchestrator.selectors import (
    DeterministicSelector,
    LLMSelector,
    ProposeAction,
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


# --- DeterministicSelector — LLM'siz kural-tabanlı seçici ---

def _det_sessions():
    """4 aktör: yalnızca 'victim' kaynağı (resource_key='upload') sahiplenir."""
    return {
        "victim": SimpleNamespace(actor=SimpleNamespace(
            role="user", name="victim", own_object_ids={"upload": "5"})),
        "attacker": SimpleNamespace(actor=SimpleNamespace(
            role="user", name="attacker", own_object_ids={})),
        "admin_actor": SimpleNamespace(actor=SimpleNamespace(
            role="admin", name="admin_actor", own_object_ids={})),
        "anonymous": SimpleNamespace(actor=SimpleNamespace(
            role="anonymous", name="anonymous", own_object_ids={})),
    }


@pytest.mark.asyncio
async def test_deterministic_selector_covers_all_hypothesis_branches():
    # Tek endpoint ("admin" + "upload" + id'li DELETE), HypothesisGenerator.deterministic()'in
    # ürettiği hemen her hipotez tipini (idor/state_change/bfla/excessive_data_exposure/
    # injection/unauthorized_access/method_bypass/csrf/mass_assignment/file_upload/stored_xss)
    # tek seferde tetikler — DeterministicSelector.next_actions'ın tüm dallarını kapsar.
    ep = Endpoint(method="DELETE", path_template="/api/admin/upload/{id}", id_param="id")
    sel = DeterministicSelector()
    actions = await sel.next_actions(None, [ep], _det_sessions())

    run_oracles = [a for a in actions if isinstance(a, RunOracle)]
    by_type: dict[str, list[RunOracle]] = {}
    for a in run_oracles:
        by_type.setdefault(a.oracle, []).append(a)

    # idor + state_change_authz: yalnızca sahip ('victim') kurban olabilir, kalan 3 aktör saldırır.
    for oracle in ("idor", "state_change_authz"):
        pairs = by_type[oracle]
        assert len(pairs) == 3
        assert {p.attacker_name for p in pairs} == {"attacker", "admin_actor", "anonymous"}
        assert all(p.victim_name == "victim" for p in pairs)

    # bfla: admin kurban, admin-olmayan herkes saldıran (admin kendine karşı hariç).
    bfla = by_type["bfla"]
    assert len(bfla) == 3
    assert {p.attacker_name for p in bfla} == {"victim", "attacker", "anonymous"}
    assert all(p.victim_name == "admin_actor" for p in bfla)

    # excessive_data_exposure + unauthorized_access: ilk uygun aktörde durur (break).
    assert by_type["excessive_data_exposure"] == [by_type["excessive_data_exposure"][0]]
    assert by_type["excessive_data_exposure"][0].victim_name == "victim"
    assert by_type["excessive_data_exposure"][0].attacker_name == "victim"
    assert len(by_type["unauthorized_access"]) == 1
    assert by_type["unauthorized_access"][0].victim_name == "victim"
    assert by_type["unauthorized_access"][0].attacker_name == "anonymous"

    # method_bypass: yalnızca sahip kurban olabilir, kalan 3 aktör saldırır.
    mb = by_type["method_bypass"]
    assert len(mb) == 3
    assert all(p.victim_name == "victim" for p in mb)

    # csrf + mass_assignment: yalnızca sahip aktör, kendine karşı (break yok ama tek eşleşen var).
    for oracle in ("csrf", "mass_assignment"):
        pairs = by_type[oracle]
        assert len(pairs) == 1
        assert pairs[0].victim_name == pairs[0].attacker_name == "victim"

    # stored_xss: sahip kurban, TÜM aktörler (kendisi dahil) saldıran olarak denenir.
    xss = by_type["stored_xss"]
    assert len(xss) == 4
    assert {p.attacker_name for p in xss} == {"victim", "attacker", "admin_actor", "anonymous"}
    assert all(p.victim_name == "victim" for p in xss)

    # injection + file_upload: yalnızca ilk aktörle (kendine karşı) bir kez denenir.
    assert len(by_type["injection"]) == 1
    assert by_type["injection"][0].victim_name == by_type["injection"][0].attacker_name == "victim"
    assert len(by_type["file_upload"]) == 1

    # Faz 4 kuyruğu: cevaplardan id çıkarma her zaman eklenir; sıralı int own-id etrafında
    # komşu tarama yalnızca int id sahibi aktör için eklenir ('victim': '5').
    inspects = [a for a in actions if isinstance(a, InspectResponseForIds)]
    assert len(inspects) == 1
    enumerates = [a for a in actions if isinstance(a, EnumerateIds)]
    assert len(enumerates) == 1
    assert enumerates[0].actor_name == "victim" and enumerates[0].around_id == "5"


@pytest.mark.asyncio
async def test_deterministic_selector_no_own_ids_skips_idor_and_enumerate():
    # Hiçbir aktör kaynağı sahiplenmiyorsa idor/state_change/excessive/unauthorized/method_bypass/
    # csrf/mass_assignment/stored_xss dallarının hepsi 'continue'/eşleşmeme ile boş kalır;
    # yalnızca injection + file_upload (kendine karşı, koşulsuz) + InspectResponseForIds kalır.
    ep = Endpoint(method="DELETE", path_template="/api/admin/upload/{id}", id_param="id")
    sessions = {
        "attacker": SimpleNamespace(actor=SimpleNamespace(role="user", name="attacker", own_object_ids={})),
        "anonymous": SimpleNamespace(actor=SimpleNamespace(role="anonymous", name="anonymous", own_object_ids={})),
    }
    sel = DeterministicSelector()
    actions = await sel.next_actions(None, [ep], sessions)

    run_oracles = {a.oracle for a in actions if isinstance(a, RunOracle)}
    assert "idor" not in run_oracles and "state_change_authz" not in run_oracles
    assert "excessive_data_exposure" not in run_oracles
    assert "method_bypass" not in run_oracles
    assert "csrf" not in run_oracles and "mass_assignment" not in run_oracles
    assert "stored_xss" not in run_oracles
    assert "injection" in run_oracles and "file_upload" in run_oracles
    assert any(isinstance(a, InspectResponseForIds) for a in actions)
    assert not any(isinstance(a, EnumerateIds) for a in actions)   # int id sahibi yok


@pytest.mark.asyncio
async def test_deterministic_selector_enumerate_skips_endpoints_without_id():
    # id'siz endpoint (has_id=False) komşu-tarama döngüsünde 'continue' ile atlanır.
    ep_no_id = Endpoint(method="GET", path_template="/api/health")
    sel = DeterministicSelector()
    actions = await sel.next_actions(None, [ep_no_id], _det_sessions())
    assert not any(isinstance(a, EnumerateIds) for a in actions)


def test_propose_action_to_action_unknown_type_returns_none():
    # Literal doğrulamasını atlayıp (model_construct) savunmacı son satırı (bilinmeyen
    # action → None) dener — normal şemadan geçerek asla ulaşılamayan defansif kod yolu.
    action = ProposeAction.model_construct(action="unknown", rationale="r")
    assert action.to_action() is None


# --- ProposeAction.to_action() — Faz 4 aksiyon tipleri (enumerate/mutate/inspect/escalate) ---

ENUMERATE = ('{"action":"enumerate_ids","path_template":"/api/x/{id}",'
             '"actor_name":"user_A","around_id":"7","rationale":"r"}')
MUTATE = ('{"action":"mutate_id_format","path_template":"/api/x/{id}",'
          '"actor_name":"user_A","base_id":"abc","rationale":"r"}')
INSPECT = '{"action":"inspect_response_for_ids","source_note":"n","rationale":"r"}'
ESCALATE = ('{"action":"escalate_role","path_template":"/api/x/{id}",'
            '"low_actor_name":"user_A","rationale":"r"}')


def test_parse_enumerate_ids_action():
    acts = _parse_actions(f"[{ENUMERATE}]")
    assert len(acts) == 1 and isinstance(acts[0], EnumerateIds)
    assert acts[0].around_id == "7" and acts[0].span == 5


def test_parse_mutate_id_format_action():
    acts = _parse_actions(f"[{MUTATE}]")
    assert len(acts) == 1 and isinstance(acts[0], MutateIdFormat)
    assert acts[0].base_id == "abc"


def test_parse_inspect_response_for_ids_action():
    # path_template gerekmez (ep'siz çalışır) — _endpoint() None dönse de bu dal etkilenmez.
    acts = _parse_actions(f"[{INSPECT}]")
    assert len(acts) == 1 and isinstance(acts[0], InspectResponseForIds)
    assert acts[0].source_note == "n"


def test_parse_escalate_role_action():
    acts = _parse_actions(f"[{ESCALATE}]")
    assert len(acts) == 1 and isinstance(acts[0], EscalateRole)
    assert acts[0].low_actor_name == "user_A"


def test_parse_enumerate_ids_missing_around_id_dropped():
    incomplete = '{"action":"enumerate_ids","path_template":"/api/x/{id}","actor_name":"user_A"}'
    assert _parse_actions(incomplete) == []


def test_parse_mutate_id_format_missing_base_id_dropped():
    incomplete = '{"action":"mutate_id_format","path_template":"/api/x/{id}","actor_name":"user_A"}'
    assert _parse_actions(incomplete) == []


def test_parse_escalate_role_missing_low_actor_dropped():
    incomplete = '{"action":"escalate_role","path_template":"/api/x/{id}"}'
    assert _parse_actions(incomplete) == []


def test_parse_probe_without_path_template_dropped():
    # _endpoint() path_template yoksa None döner → probe ep gerektirdiği için elenir.
    incomplete = '{"action":"probe","actor_name":"user_A","rationale":"r"}'
    assert _parse_actions(incomplete) == []


# --- _parse_actions savunmacı ayrıştırma yolları ---

def test_parse_actions_recovers_embedded_array_from_prose():
    text = f"Şöyle yapalım: [{RUN}] tamamdır."
    acts = _parse_actions(text)
    assert len(acts) == 1 and isinstance(acts[0], RunOracle)


def test_parse_actions_no_brackets_returns_empty():
    assert _parse_actions("hiçbir aksiyon önerilmiyor, düz metin") == []


def test_parse_actions_bad_embedded_json_returns_empty():
    assert _parse_actions("prefix [ bu geçerli json değil ] suffix") == []


def test_parse_actions_top_level_scalar_returns_empty():
    assert _parse_actions("42") == []


def test_parse_actions_skips_non_dict_items():
    assert _parse_actions("[1, 2, 3]") == []


def test_parse_actions_skips_invalid_pydantic_item():
    # action alanı Literal enum dışında → ProposeAction ValidationError → sessizce elenir.
    assert _parse_actions('[{"action":"not_a_real_action"}]') == []
