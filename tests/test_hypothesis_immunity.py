"""Immunity-memory — GOREVLER #15 (kaynak: HIVE). Dosya G/Ç yalnızca `tmp_path` üzerinde
(ağsız); yalnızca CONFIRMED bulguların öğrenildiğini, bozuk dosyanın taramayı çökertmediğini ve
booster'ın yalnızca oracle-testable türler için hipotez ürettiğini kanıtlar.
"""
import json

from pentestai.hypothesis import ImmunityHypothesisBooster, ImmunityMemoryStore
from pentestai.models import Endpoint, Evidence, Finding
from pentestai.models.immunity import ImmunitySignature


def _finding(type_="idor", method="GET", endpoint="/api/orders/{id}", verdict="CONFIRMED"):
    return Finding(id="F-001", type=type_, method=method, endpoint=endpoint,
                   verdict=verdict, evidence=Evidence())


# --------------------------- ImmunityMemoryStore ---------------------------

def test_record_learns_only_confirmed(tmp_path):
    store = ImmunityMemoryStore(str(tmp_path / "mem.json"))
    findings = [_finding(verdict="CONFIRMED"), _finding(verdict="LIKELY", endpoint="/x"),
               _finding(verdict="REJECTED", endpoint="/y"), _finding(verdict="INCONCLUSIVE", endpoint="/z")]
    sigs = store.record(findings)
    assert len(sigs) == 1 and sigs[0].path_template == "/api/orders/{id}"


def test_record_persists_to_disk(tmp_path):
    path = tmp_path / "mem.json"
    ImmunityMemoryStore(str(path)).record([_finding()])
    assert path.exists()
    raw = json.loads(path.read_text(encoding="utf-8"))
    assert raw[0]["pattern"] == "idor:GET:/api/orders/{id}"


def test_record_increments_confirmed_count_on_repeat(tmp_path):
    store = ImmunityMemoryStore(str(tmp_path / "mem.json"))
    store.record([_finding()])
    sigs = store.record([_finding()])   # aynı örüntü ikinci kez
    assert len(sigs) == 1 and sigs[0].confirmed_count == 2


def test_record_merges_with_existing_library(tmp_path):
    path = tmp_path / "mem.json"
    ImmunityMemoryStore(str(path)).save([
        ImmunitySignature(pattern="bfla:GET:/api/admin", type="bfla", method="GET",
                          path_template="/api/admin", confirmed_count=3),
    ])
    sigs = ImmunityMemoryStore(str(path)).record([_finding()])   # farklı örüntü ekler
    patterns = {s.pattern for s in sigs}
    assert patterns == {"bfla:GET:/api/admin", "idor:GET:/api/orders/{id}"}
    bfla = next(s for s in sigs if s.type == "bfla")
    assert bfla.confirmed_count == 3   # dokunulmadı


def test_load_returns_empty_list_when_file_missing(tmp_path):
    assert ImmunityMemoryStore(str(tmp_path / "yok.json")).load() == []


def test_load_recovers_from_corrupt_file(tmp_path):
    path = tmp_path / "mem.json"
    path.write_text("{ bozuk json", encoding="utf-8")
    assert ImmunityMemoryStore(str(path)).load() == []


def test_load_skips_invalid_records_but_keeps_valid_ones(tmp_path):
    path = tmp_path / "mem.json"
    path.write_text(json.dumps([
        {"pattern": "idor:GET:/x", "type": "idor", "method": "GET", "path_template": "/x"},
        {"not": "a valid signature"},
    ]), encoding="utf-8")
    sigs = ImmunityMemoryStore(str(path)).load()
    assert len(sigs) == 1 and sigs[0].pattern == "idor:GET:/x"


# --------------------------- ImmunityHypothesisBooster ---------------------------

def test_boost_returns_empty_when_memory_empty(tmp_path):
    booster = ImmunityHypothesisBooster(ImmunityMemoryStore(str(tmp_path / "mem.json")))
    assert booster.boost([Endpoint(method="GET", path_template="/api/orders/{id}")]) == []


def test_boost_matches_same_pattern_new_endpoint(tmp_path):
    store = ImmunityMemoryStore(str(tmp_path / "mem.json"))
    store.record([_finding(type_="idor", method="GET", endpoint="/api/orders/{id}")])
    booster = ImmunityHypothesisBooster(store)
    hyps = booster.boost([Endpoint(method="GET", path_template="/api/orders/{id}")])
    assert len(hyps) == 1 and hyps[0].type == "idor"
    assert "immunity memory" in hyps[0].rationale
    assert "1 kez" in hyps[0].rationale


def test_boost_ignores_non_matching_endpoint(tmp_path):
    store = ImmunityMemoryStore(str(tmp_path / "mem.json"))
    store.record([_finding(endpoint="/api/orders/{id}")])
    booster = ImmunityHypothesisBooster(store)
    hyps = booster.boost([Endpoint(method="GET", path_template="/api/products/{id}")])
    assert hyps == []


def test_boost_skips_non_boostable_learned_type(tmp_path):
    # 'exposure' Hypothesis.type Literal'inde YOK (yalnızca detector üretir) → sessizce atlanır.
    path = tmp_path / "mem.json"
    ImmunityMemoryStore(str(path)).save([
        ImmunitySignature(pattern="exposure:GET:/.env", type="exposure", method="GET",
                          path_template="/.env"),
    ])
    booster = ImmunityHypothesisBooster(ImmunityMemoryStore(str(path)))
    hyps = booster.boost([Endpoint(method="GET", path_template="/.env")])
    assert hyps == []
