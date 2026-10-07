"""HypothesisGenerator + LLM parse. DESIGN.md §14 (Stage 1)."""
import pytest

from pentestai.llm import MockLLMClient
from pentestai.llm.client import _parse_hypotheses
from pentestai.models import Endpoint, Hypothesis
from pentestai.planner import HypothesisGenerator

EPS = [
    Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id"),
    Endpoint(method="GET", path_template="/api/admin/config", id_param="id"),
    Endpoint(method="GET", path_template="/api/health", id_param="id"),
    Endpoint(method="PUT", path_template="/api/orders/{id}", id_param="id"),
    Endpoint(method="POST", path_template="/api/uploads", id_param="id"),
]


def test_deterministic_rules():
    hs = HypothesisGenerator().deterministic(EPS)
    types = {(h.type, h.endpoint.path_template, h.endpoint.method) for h in hs}
    assert ("idor", "/api/orders/{id}", "GET") in types     # path param → IDOR
    assert ("excessive_data_exposure", "/api/orders/{id}", "GET") in types  # obje → BOPLA
    assert ("bfla", "/api/admin/config", "GET") in types     # admin → BFLA
    plain_types = {(h.type, h.endpoint.path_template) for h in hs}
    assert ("idor", "/api/health") not in plain_types       # id yok → aday değil
    # B1: csrf + mass_assignment yalnızca yazma-metodu + id'li endpoint'te
    assert ("csrf", "/api/orders/{id}", "PUT") in types
    assert ("mass_assignment", "/api/orders/{id}", "PUT") in types
    assert ("state_change_authz", "/api/orders/{id}", "PUT") in types
    # B1: file_upload — path'inde "upload" geçen endpoint
    assert ("file_upload", "/api/uploads", "POST") in types
    assert ("csrf", "/api/uploads", "POST") not in types    # yazma metodu var ama id yok


@pytest.mark.asyncio
async def test_generate_merges_llm_and_dedupes():
    canned = [Hypothesis(type="idor", endpoint=Endpoint(path_template="/api/carts/{id}"))]
    gen = HypothesisGenerator(MockLLMClient(canned))
    hs = await gen.generate(EPS)
    paths = {(h.type, h.endpoint.path_template) for h in hs}
    assert ("idor", "/api/carts/{id}") in paths       # LLM'den
    assert ("idor", "/api/orders/{id}") in paths       # deterministik
    # dedupe: aynı (type, method, path) tek kez
    assert len(hs) == len({(h.type, h.endpoint.method, h.endpoint.path_template) for h in hs})


def test_llm_parse_valid_json():
    text = '[{"type":"idor","path_template":"/api/x/{id}","id_param":"id"}]'
    hs = _parse_hypotheses(text)
    assert len(hs) == 1 and hs[0].type == "idor" and hs[0].source == "llm"


def test_llm_parse_ignores_prose_and_bad_items():
    text = 'İşte adaylar: [{"type":"bfla","path_template":"/api/admin"},{"bad":1}] bitti'
    hs = _parse_hypotheses(text)
    assert len(hs) == 1 and hs[0].type == "bfla"     # geçersiz öğe atıldı, prose yok sayıldı
