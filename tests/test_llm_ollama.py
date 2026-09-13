"""OllamaLLMClient — network'süz (httpx.MockTransport). Faz 0.1.

format:json zorlamasını, temperature akışını ve yanıt parse'ını doğrular.
"""
import json

import httpx
import pytest

from pentestai.llm.client import OllamaLLMClient


def _transport(capture: dict, content: str) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        capture["payload"] = json.loads(request.content)
        capture["url"] = str(request.url)
        return httpx.Response(200, json={"message": {"role": "assistant", "content": content}})

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_complete_sends_format_json_and_default_temperature():
    cap: dict = {}
    client = OllamaLLMClient(transport=_transport(cap, "[]"))
    out = await client.complete("sistem", "kullanici")

    assert cap["payload"]["format"] == "json"            # local modeli geçerli JSON'a zorla
    assert cap["payload"]["options"]["temperature"] == 0  # varsayılan tekrar-üretilebilir
    assert cap["payload"]["stream"] is False
    assert out == "[]"                                    # message.content doğru çıkarıldı


@pytest.mark.asyncio
async def test_temperature_param_is_threaded_into_options():
    cap: dict = {}
    client = OllamaLLMClient(temperature=0.7, transport=_transport(cap, "{}"))
    await client.complete("s", "u")
    assert cap["payload"]["options"]["temperature"] == 0.7


@pytest.mark.asyncio
async def test_think_key_omitted_by_default():
    # Klasik instruct modelleri için "think" anahtarı HİÇ gönderilmez (geriye uyum).
    cap: dict = {}
    client = OllamaLLMClient(transport=_transport(cap, "[]"))
    await client.complete("s", "u")
    assert "think" not in cap["payload"]


@pytest.mark.asyncio
async def test_think_false_is_sent_and_keeps_format_json():
    # Reasoning modelinde düşünme kapatılınca payload'a think:false eklenir; JSON zorlaması korunur.
    cap: dict = {}
    client = OllamaLLMClient(think=False, transport=_transport(cap, "[]"))
    await client.complete("s", "u")
    assert cap["payload"]["think"] is False
    assert cap["payload"]["format"] == "json"


@pytest.mark.asyncio
async def test_think_true_is_threaded_into_payload():
    cap: dict = {}
    client = OllamaLLMClient(think=True, transport=_transport(cap, "{}"))
    await client.complete("s", "u")
    assert cap["payload"]["think"] is True


@pytest.mark.asyncio
async def test_propose_hypotheses_parses_typed_result():
    content = '[{"type":"bfla","path_template":"/api/admin","method":"GET"}]'
    client = OllamaLLMClient(transport=_transport({}, content))
    hyps = await client.propose_hypotheses("GET /api/admin")
    assert len(hyps) == 1
    assert hyps[0].type == "bfla" and hyps[0].source == "llm"


@pytest.mark.asyncio
async def test_propose_sends_json_schema_as_format():
    # propose_hypotheses, Ollama'ya format olarak JSON ŞEMA (sözlük) geçirir (structured outputs).
    cap: dict = {}
    client = OllamaLLMClient(transport=_transport(cap, '{"hypotheses":[]}'))
    await client.propose_hypotheses("GET /api/x/{id}")
    fmt = cap["payload"]["format"]
    assert isinstance(fmt, dict)                       # "json" string'i değil, tam şema
    assert "hypotheses" in fmt["properties"]


@pytest.mark.asyncio
async def test_wrapper_object_is_parsed():
    # Local modelin tipik biçimi: {"hypotheses":[...]} — toleranslı parse bunu çözer.
    content = '{"hypotheses":[{"type":"idor","path_template":"/api/x/{id}","rationale":"r"}]}'
    client = OllamaLLMClient(transport=_transport({}, content))
    hyps = await client.propose_hypotheses("GET /api/x/{id}")
    assert len(hyps) == 1 and hyps[0].type == "idor" and hyps[0].source == "llm"


@pytest.mark.asyncio
async def test_single_object_is_parsed():
    # Dizi yerine tek nesne dönerse de kabul edilir (qwen3.8 think=True bunu yapıyordu).
    content = '{"type":"bfla","path_template":"/api/admin","method":"GET","rationale":"r"}'
    client = OllamaLLMClient(transport=_transport({}, content))
    hyps = await client.propose_hypotheses("GET /api/admin")
    assert len(hyps) == 1 and hyps[0].type == "bfla"


@pytest.mark.asyncio
async def test_error_object_yields_no_hypotheses():
    # format:"json"'ın bozuk çıktısı ({"error":...}) şemaya uymaz → sessizce [] döner (crash yok).
    client = OllamaLLMClient(transport=_transport({}, '{"error":"Invalid JSON structure."}'))
    assert await client.propose_hypotheses("GET /api/x/{id}") == []


@pytest.mark.asyncio
async def test_malformed_json_is_dropped_without_crash():
    # Model bozuk/eksik çıktı verse bile sessizce elenir (crash yok) — kabul kriteri.
    client = OllamaLLMClient(transport=_transport({}, "üzgünüm, JSON veremedim"))
    hyps = await client.propose_hypotheses("GET /api/x/{id}")
    assert hyps == []


@pytest.mark.asyncio
async def test_payload_disables_thinking():
    # Qwen3 gibi düşünen modelde reasoning kapatılır → num_predict bütçesi JSON'a kalır.
    cap: dict = {}
    client = OllamaLLMClient(transport=_transport(cap, "[]"))
    await client.complete("s", "u")
    assert cap["payload"]["think"] is False


@pytest.mark.asyncio
async def test_think_block_is_stripped_before_parse():
    # Düşünen model think:false'a uymayıp <think>...</think> koyarsa: blok '[' / ']' içerir ve
    # eski find/rfind kesici bozuk dilim alırdı. Strip sayesinde temiz JSON dizi parse edilir.
    content = (
        "<think>Kullanıcı /api/x[0] gibi id'leri denemeli, [id] parametresi kritik.</think>"
        '[{"type":"idor","path_template":"/api/x/{id}","method":"GET"}]'
    )
    client = OllamaLLMClient(transport=_transport({}, content))
    hyps = await client.propose_hypotheses("GET /api/x/{id}")
    assert len(hyps) == 1
    assert hyps[0].type == "idor"


@pytest.mark.asyncio
async def test_non_200_raises_runtime_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    client = OllamaLLMClient(transport=httpx.MockTransport(handler))
    with pytest.raises(RuntimeError):
        await client.complete("s", "u")
