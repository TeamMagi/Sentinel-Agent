"""AirgapPolicy — RK-11 (GOREVLER.md Dalga 3): --offline modunda bulut LLM bloklanır.

Saf karar kapısı (ağ yok) + CLI'nin `_build_llm`'inin bunu gerçekten önceden çağırdığını
doğrular. Network yok.
"""
from types import SimpleNamespace

import pytest

from pentestai.airgap import ALLOWED_OFFLINE_PROVIDERS, AirgapPolicy, AirgapViolation
from pentestai.cli import _build_llm
from pentestai.llm import OllamaLLMClient


def test_disabled_policy_is_a_noop_for_any_provider():
    policy = AirgapPolicy(enabled=False)
    for provider in ("anthropic", "gemini", "ollama", "none", "anything"):
        policy.authorize_llm_provider(provider)   # raise atmaz
    assert policy.blocked == []


@pytest.mark.parametrize("provider", sorted(ALLOWED_OFFLINE_PROVIDERS))
def test_enabled_policy_allows_local_and_no_llm(provider):
    policy = AirgapPolicy(enabled=True)
    policy.authorize_llm_provider(provider)   # raise atmaz
    assert policy.blocked == []


@pytest.mark.parametrize("provider", ["anthropic", "gemini"])
def test_enabled_policy_blocks_and_logs_cloud_provider(provider):
    policy = AirgapPolicy(enabled=True)
    with pytest.raises(AirgapViolation):
        policy.authorize_llm_provider(provider)
    assert policy.blocked == [provider]   # bloklanan denemeler izlenir (log/rapor için)


def _ns(**kw):
    base = dict(llm=None, llm_config=None, llm_model=None, offline=False)
    base.update(kw)
    return SimpleNamespace(**base)


def test_cli_build_llm_raises_before_constructing_cloud_client_when_offline():
    with pytest.raises(AirgapViolation):
        _build_llm(_ns(llm="anthropic", offline=True))
    with pytest.raises(AirgapViolation):
        _build_llm(_ns(llm="gemini", offline=True))


def test_cli_build_llm_allows_ollama_when_offline():
    client = _build_llm(_ns(llm="ollama", offline=True))
    assert isinstance(client, OllamaLLMClient)


def test_cli_build_llm_allows_no_llm_when_offline():
    assert _build_llm(_ns(llm=None, offline=True)) is None


def test_cli_build_llm_allows_cloud_provider_when_not_offline():
    # --offline verilmemişse davranış hiç değişmez (geriye dönük uyumlu).
    client = _build_llm(_ns(llm="anthropic", offline=False))
    assert client is not None
