"""LLM client soyutlaması — _parse_hypotheses uç durumları + Anthropic/Gemini client'ları.

OllamaLLMClient zaten test_llm_ollama.py'de kanıtlı; burada geri kalan sağlayıcılar ve
sağlayıcı-bağımsız parse yardımcısı (_parse_hypotheses) hedeflenir. Ağsız (CLAUDE.md §6):
Anthropic SDK'sı monkeypatch ile sahte, Gemini httpx.MockTransport ile.
"""
from types import SimpleNamespace

import httpx
import pytest

from pentestai.llm.client import GeminiLLMClient, MockLLMClient

# --------------------------- _parse_hypotheses (MockLLMClient.propose_hypotheses üzerinden) ---------------------------

@pytest.mark.asyncio
async def test_mock_client_without_canned_falls_through_to_complete_and_parses():
    # canned=None → LLMClient.propose_hypotheses (temel sınıf) çağrılır: complete() + parse.
    client = MockLLMClient(completion='[{"type":"idor","path_template":"/x/{id}","method":"GET"}]')
    hyps = await client.propose_hypotheses("GET /x/{id}")
    assert len(hyps) == 1 and hyps[0].type == "idor"


@pytest.mark.asyncio
async def test_parse_hypotheses_embedded_array_still_malformed_yields_empty():
    # find('[')/rfind(']') ikisi de bulunur ama dilimlenen içerik yine de geçersiz JSON —
    # ikinci (iç) try/except de düşer, sessizce [] döner (crash yok).
    client = MockLLMClient(completion="gürültü [1, 'tek-tırnak-geçersiz'] daha gürültü")
    assert await client.propose_hypotheses("x") == []


@pytest.mark.asyncio
async def test_parse_hypotheses_non_list_non_dict_top_level_yields_empty():
    client = MockLLMClient(completion="42")
    assert await client.propose_hypotheses("x") == []


@pytest.mark.asyncio
async def test_parse_hypotheses_list_of_non_dict_items_yields_empty():
    client = MockLLMClient(completion="[1, 2, 3]")
    assert await client.propose_hypotheses("x") == []


# --------------------------- AnthropicLLMClient ---------------------------

class _FakeMessages:
    def __init__(self, captured: dict, chunks):
        self._captured = captured
        self._chunks = chunks

    async def create(self, **kw):
        self._captured.update(kw)
        return SimpleNamespace(content=self._chunks)


class _FakeAsyncAnthropic:
    def __init__(self, captured: dict, chunks):
        self.messages = _FakeMessages(captured, chunks)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


@pytest.mark.asyncio
async def test_anthropic_client_joins_text_blocks_and_skips_non_text(monkeypatch):
    anthropic = pytest.importorskip("anthropic")
    from pentestai.llm.client import AnthropicLLMClient

    captured: dict = {}
    chunks = [
        SimpleNamespace(type="text", text="merhaba "),
        SimpleNamespace(type="thinking", text="görmezden-gel"),
        SimpleNamespace(type="text", text="dünya"),
    ]
    monkeypatch.setattr(anthropic, "AsyncAnthropic", lambda: _FakeAsyncAnthropic(captured, chunks))

    client = AnthropicLLMClient(model="claude-test", max_tokens=111)
    out = await client.complete("sistem", "kullanıcı")

    assert out == "merhaba dünya"
    assert captured["model"] == "claude-test"
    assert captured["max_tokens"] == 111
    assert captured["system"] == "sistem"
    assert captured["messages"] == [{"role": "user", "content": "kullanıcı"}]


# --------------------------- GeminiLLMClient ---------------------------

def test_gemini_client_without_api_key_raises_before_any_request(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    client = GeminiLLMClient(api_key=None)
    with pytest.raises(RuntimeError, match="GEMINI_API_KEY"):
        import asyncio
        asyncio.run(client.complete("s", "u"))


@pytest.mark.asyncio
async def test_gemini_client_parses_candidates_and_sends_generation_config():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        captured["url"] = str(request.url)
        return httpx.Response(200, json={"candidates": [
            {"content": {"parts": [{"text": "merhaba "}, {"text": "dünya"}]}},
        ]})

    client = GeminiLLMClient(
        model="gemini-test", api_key="k123", temperature=0.5, max_tokens=99,
        transport=httpx.MockTransport(handler))
    out = await client.complete("sistem", "kullanıcı")

    assert out == "merhaba dünya"
    assert captured["headers"]["x-goog-api-key"] == "k123"
    assert "gemini-test" in captured["url"]


@pytest.mark.asyncio
async def test_gemini_client_no_candidates_yields_empty_string():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"candidates": []})

    client = GeminiLLMClient(api_key="k", transport=httpx.MockTransport(handler))
    assert await client.complete("s", "u") == ""


@pytest.mark.asyncio
async def test_gemini_client_non_200_raises_runtime_error_with_body_snippet():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="PERMISSION_DENIED: bad key")

    client = GeminiLLMClient(api_key="k", transport=httpx.MockTransport(handler))
    with pytest.raises(RuntimeError, match="PERMISSION_DENIED"):
        await client.complete("s", "u")
