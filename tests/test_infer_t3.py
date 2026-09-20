"""LLM'siz çıkarım (T3) — id tipi · id parametresi · id havuzu · şema-marker öğrenimi.

Network YOK. Kabul (GOREVLER.md T3): hipotez üretiminin LLM'siz kolu path şablonundan,
OpenAPI/HAR tip bilgisinden, crawl'dan öğrenilen id havuzundan ve yanıt şemasından
otomatik marker adayından beslenir.

En kritik test `test_uuid_object_id_echo_is_not_confirmed`: şema-öğrenicisi UUID biçimli
bir obje id'sini şeklinden ötürü aday sanabilirdi; saldırgan id'yi kendisi gönderdiği için
cevapta echo'lanması IDOR kanıtı DEĞİLDİR (markers.py'deki klasik tuzak).
"""
import httpx
import pytest

from pentestai.idtypes import (
    INTEGER,
    OBJECTID,
    OPAQUE,
    STRING,
    UNKNOWN,
    UUID,
    IdTypeInferrer,
)
from pentestai.models import Actor, AuthState, Endpoint, NormalizedResponse, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import IdorOracle, base
from pentestai.oracle.marker_schema import SchemaMarkerLearner
from pentestai.oracle.markers import MarkerExtractor
from pentestai.policy import PolicyEngine
from pentestai.recon.har import HarRecon
from pentestai.recon.infer import IdParamInferrer, IdPool
from pentestai.recon.openapi import OpenApiRecon

BASE = "http://localhost:3000"


# ---------------- id tipi ----------------

def test_id_type_from_value_covers_every_shape():
    assert IdTypeInferrer.from_value("12345") == INTEGER
    assert IdTypeInferrer.from_value(7) == INTEGER
    assert IdTypeInferrer.from_value("9f1c2d3e-4a5b-6c7d-8e9f-0a1b2c3d4e5f") == UUID
    assert IdTypeInferrer.from_value("507f1f77bcf86cd799439011") == OBJECTID
    assert IdTypeInferrer.from_value("ord-2026-abc123xyz") == OPAQUE
    assert IdTypeInferrer.from_value("basket") == STRING
    assert IdTypeInferrer.from_value("") == UNKNOWN
    # bool int'in alt tipidir — integer sanılmamalı
    assert IdTypeInferrer.from_value(True) == UNKNOWN


def test_id_type_from_openapi_schema():
    assert IdTypeInferrer.from_openapi_schema({"type": "integer"}) == INTEGER
    assert IdTypeInferrer.from_openapi_schema({"type": "string", "format": "uuid"}) == UUID
    assert IdTypeInferrer.from_openapi_schema({"type": "string"}) == STRING
    # biçim verilmemiş ama pattern UUID'yi anlatıyor
    assert IdTypeInferrer.from_openapi_schema(
        {"type": "string", "pattern": "^[0-9a-fA-F]{8}-"}) == UUID
    assert IdTypeInferrer.from_openapi_schema(None) == UNKNOWN


def test_id_type_from_openapi_schema_unhandled_type_is_unknown():
    # "boolean"/"array"/"object" gibi ne integer ne string olan tipler → UNKNOWN'a düşer
    # (bilinmeyen bir OpenAPI tipini sessizce STRING/INTEGER sanmak yanlış bogus id üretirdi).
    assert IdTypeInferrer.from_openapi_schema({"type": "boolean"}) == UNKNOWN
    assert IdTypeInferrer.from_openapi_schema({}) == UNKNOWN


def test_bogus_id_is_format_valid_per_type():
    # Tipe uygun bogus: biçim GEÇERLİ olmalı ki sunucu 400 "malformed" değil 404 yoluna girsin.
    assert IdTypeInferrer.from_value(IdTypeInferrer.bogus_for(UUID)) == UUID
    assert IdTypeInferrer.from_value(IdTypeInferrer.bogus_for(OBJECTID)) == OBJECTID
    assert IdTypeInferrer.from_value(IdTypeInferrer.bogus_for(INTEGER)) == INTEGER
    assert IdTypeInferrer.bogus_for(UNKNOWN) == "999999999"   # geriye uyum
    assert IdTypeInferrer.bogus_for(None) == "999999999"


# ---------------- id parametresi ----------------

def test_id_param_inferrer_picks_innermost_object():
    inf = IdParamInferrer()
    assert inf.infer("/api/users/{uid}/orders/{orderId}") == "orderId"
    assert inf.infer("/api/orders/{id}") == "id"
    assert inf.infer("/api/orders/{order_id}") == "order_id"


def test_id_param_inferrer_skips_presentation_params():
    # /reports/{format} obje endpoint'i DEĞİL; onu id sanmak boşa hipotez üretir.
    inf = IdParamInferrer()
    assert inf.infer("/reports/{format}") is None
    assert inf.infer("/api/docs/{lang}/{page}") is None
    # id-benzeri bir parametre varsa sunum parametresi yerine O seçilir
    assert inf.infer("/api/users/{userId}/export/{format}") == "userId"


def test_id_param_inferrer_ignores_pathless_template():
    assert IdParamInferrer().infer("/api/products") is None
    assert IdParamInferrer().infer("") is None


# ---------------- id havuzu ----------------

def test_id_pool_preserves_order_and_dedupes():
    pool = IdPool()
    pool.add("order", ["A-1", "A-2", "A-1"])
    pool.add("order", ["A-3"])
    assert pool.get("order") == ["A-1", "A-2", "A-3"]
    assert pool.first("order") == "A-1"
    assert pool.resources() == ["order"]


def test_id_pool_infers_type_from_first_id():
    pool = IdPool()
    pool.add("basket", ["8", "9"])
    assert pool.id_type("basket") == INTEGER
    assert pool.id_type("yok") == UNKNOWN
    assert pool.as_dict() == {"basket": ["8", "9"]}


def test_id_pool_ignores_empty_key_and_values():
    pool = IdPool()
    pool.add("", ["x"])
    pool.add("order", ["", "  ", "ok"])
    assert pool.resources() == ["order"] and pool.get("order") == ["ok"]


# ---------------- OpenAPI / HAR tip bilgisi ----------------

def test_openapi_reads_id_type_from_schema():
    spec = {"paths": {"/api/orders/{orderId}": {
        "get": {"parameters": [
            {"name": "orderId", "in": "path", "schema": {"type": "string", "format": "uuid"}}]}}}}
    eps = OpenApiRecon().parse(spec)
    assert len(eps) == 1
    assert eps[0].id_param == "orderId" and eps[0].id_type == UUID


def test_openapi_supports_swagger2_inline_type_and_path_level_params():
    # Swagger 2: type/format doğrudan parametrede; parametreler path-item seviyesinde.
    spec = {"paths": {"/api/orders/{id}": {
        "parameters": [{"name": "id", "in": "path", "type": "integer"}],
        "get": {}}}}
    assert OpenApiRecon().parse(spec)[0].id_type == INTEGER


def test_openapi_unknown_type_when_no_parameter_metadata():
    spec = {"paths": {"/api/orders/{id}": {"get": {}}}}
    assert OpenApiRecon().parse(spec)[0].id_type == UNKNOWN


def test_har_infers_id_type_from_concrete_segment():
    def entry(url):
        return {"request": {"method": "GET", "url": url},
                "response": {"content": {"mimeType": "application/json"}}}
    har = {"log": {"entries": [
        entry("http://t/api/orders/12345"),
        entry("http://t/api/carts/9f1c2d3e-4a5b-6c7d-8e9f-0a1b2c3d4e5f"),
    ]}}
    eps = {e.path_template: e for e in HarRecon().parse(har)}
    assert eps["/api/orders/{id}"].id_type == INTEGER
    assert eps["/api/carts/{id}"].id_type == UUID


def test_har_endpoint_without_id_stays_unknown():
    har = {"log": {"entries": [{"request": {"method": "GET", "url": "http://t/api/products"},
                                "response": {"content": {"mimeType": "application/json"}}}]}}
    eps = HarRecon().parse(har)
    assert eps[0].path_template == "/api/products" and eps[0].id_type == UNKNOWN


# ---------------- şema-tabanlı marker öğrenimi ----------------

def _resp(body: dict) -> NormalizedResponse:
    import json
    return NormalizedResponse(status=200, body_text=json.dumps(body), json_body=body)


def test_learner_finds_identifying_shapes_under_unknown_key_names():
    # Sabit anahtar listesinde OLMAYAN alanlar: değerin ŞEKLİ yakalar.
    r = _resp({"policyNo": "TR330006100519786457841326",           # IBAN
               "contact": "+905551112233",                          # E.164
               "owner": "alice@test.local",                         # e-posta
               "sessionRef": "a1b2c3d4e5f6a7b8c9"})                 # uzun opak token
    got = SchemaMarkerLearner().learn(r)
    assert "TR330006100519786457841326" in got
    assert "+905551112233" in got
    assert "alice@test.local" in got
    assert "a1b2c3d4e5f6a7b8c9" in got


def test_learner_rejects_low_entropy_and_shared_values():
    # Serbest metin / kısa değer / sayı / bool marker OLAMAZ — paylaşılan veri FP üretirdi.
    r = _resp({"status": "active", "name": "Apple Juice (1000ml)",
               "qty": 3, "inStock": True, "code": "AB12"})
    assert SchemaMarkerLearner().learn(r) == []


def test_learner_skips_volatile_keys():
    # ResponseNormalizer bu anahtarları <volatile> yapar → oradan öğrenilen marker
    # body_normalized'da ASLA eşleşemezdi; sessiz ölü aday yerine baştan elenir.
    r = _resp({"uuid": "9f1c2d3e-4a5b-6c7d-8e9f-0a1b2c3d4e5f",
               "createdAt": "2026-09-18T10:00:00.000000Z"})
    assert SchemaMarkerLearner().learn(r) == []


def test_learner_honors_exclude_list():
    oid = "9f1c2d3e-4a5b-6c7d-8e9f-0a1b2c3d4e5f"
    r = _resp({"orderId": oid, "owner": "alice@test.local"})
    got = SchemaMarkerLearner().learn(r, exclude=[oid])
    assert oid not in got and "alice@test.local" in got


def test_learner_returns_empty_for_non_json_body():
    assert SchemaMarkerLearner().learn(NormalizedResponse(status=200, body_text="plain")) == []


def test_learner_caps_at_max_candidates():
    # 25'ten fazla ayırt edici alan varsa öğrenici sonsuza kadar toplamamalı — bir tavan olmalı
    # (aksi halde geniş bir yanıt gövdesi oracle'a devasa bir marker listesi taşırdı).
    body = {f"field{i}": f"alice{i}@test.local" for i in range(30)}
    got = SchemaMarkerLearner(max_candidates=5).learn(_resp(body))
    assert len(got) == 5


def test_marker_extractor_merges_learner_candidates_and_applies_exclude():
    r = _resp({"email": "alice@test.local", "sessionRef": "a1b2c3d4e5f6a7b8c9"})
    plain = MarkerExtractor().extract(r)
    assert "a1b2c3d4e5f6a7b8c9" not in plain          # anahtar adı listede yok → kaçırılırdı
    with_learner = MarkerExtractor(learner=SchemaMarkerLearner()).extract(r)
    assert "a1b2c3d4e5f6a7b8c9" in with_learner and "alice@test.local" in with_learner
    excluded = MarkerExtractor(learner=SchemaMarkerLearner()).extract(
        r, exclude=["a1b2c3d4e5f6a7b8c9"])
    assert "a1b2c3d4e5f6a7b8c9" not in excluded


def test_marker_extractor_survives_broken_learner():
    class Boom:
        def learn(self, resp, exclude=None):
            raise RuntimeError("öğrenici patladı")
    # Öğrenici hatası taramayı ÇÖKERTMEMELİ; anahtar-tabanlı çıkarım devam eder.
    got = MarkerExtractor(learner=Boom()).extract(_resp({"email": "alice@test.local"}))
    assert got == ["alice@test.local"]


# ---------------- oracle entegrasyonu: tip-farkında bogus + echo tuzağı ----------------

VICTIM_UUID = "11111111-1111-4111-8111-111111111111"
ATTACKER_UUID = "22222222-2222-4222-8222-222222222222"
UUID_DB = {
    VICTIM_UUID: {"orderId": VICTIM_UUID, "owner": "user_A", "note": "kurbanin siparisi"},
    ATTACKER_UUID: {"orderId": ATTACKER_UUID, "owner": "user_B", "note": "saldirganin siparisi"},
}
UUID_ENDPOINT = Endpoint(method="GET", path_template="/api/orders/{id}",
                         id_param="id", id_type=UUID)


def _uuid_setup(handler, endpoint=UUID_ENDPOINT):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(transport=httpx.MockTransport(handler))
    A = Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer TOKEN_A"}),
              own_object_ids={"order": VICTIM_UUID})
    B = Actor(name="user_B", auth=AuthState(headers={"Authorization": "Bearer TOKEN_B"}),
              own_object_ids={"order": ATTACKER_UUID})
    oracle = IdorOracle(Replayer(PolicyEngine(scope)), BASE)
    return store, oracle, store.create(A), store.create(B), endpoint


@pytest.mark.asyncio
async def test_negative_control_uses_type_correct_bogus_id():
    # UUID bekleyen API'ye "999999999" gitmemeli: 400 "malformed" üretir, bu "kaynak yok"
    # DEĞİLDİR. Tipe uygun bogus id sunucuyu gerçek 404 yoluna sokar.
    seen: list[str] = []

    def handler(request):
        oid = request.url.path.rsplit("/", 1)[-1]
        seen.append(oid)
        if oid not in UUID_DB:
            # Gerçek API davranışı: biçimi bozuk id 400, biçimi geçerli ama yok olan 404.
            try:
                import uuid as _u
                _u.UUID(oid)
            except ValueError:
                return httpx.Response(400, json={"error": "malformed uuid"})
            return httpx.Response(404, json={"error": "not found"})
        return httpx.Response(200, json=UUID_DB[oid])

    store, oracle, A, B, ep = _uuid_setup(handler)
    f = await oracle.run(ep, A, B, resource_key="order")
    assert "999999999" not in seen, "tip-körü bogus id kullanıldı"
    assert any(s.count("-") == 4 for s in seen), "UUID biçimli bogus id gönderilmedi"
    assert f.evidence.negative_control is True
    await store.aclose_all()


@pytest.mark.asyncio
async def test_uuid_object_id_echo_is_not_confirmed():
    # FP TUZAĞI (200 yolu — 403'e düşüp sınamayı atlamasın): yetkilendirme DÜZGÜN, sunucu
    # istenen id ne olursa olsun ÇAĞIRANIN KENDİ objesini döndürüyor ama istenen id'yi
    # `requested` alanında echo'luyor. Şema-öğrenicisi UUID'yi "ayırt edici" bulur; kurbanın
    # id'si saldırganın cevabında görünür — ama onu saldırgan KENDİSİ gönderdi → kanıt DEĞİL.
    def handler(request):
        oid = request.url.path.rsplit("/", 1)[-1]
        token = request.headers.get("authorization", "")
        owner = {"Bearer TOKEN_A": "user_A", "Bearer TOKEN_B": "user_B"}.get(token)
        own_id = VICTIM_UUID if owner == "user_A" else ATTACKER_UUID
        if oid not in UUID_DB:
            return httpx.Response(404, json={"error": "not found"})
        # her zaman çağıranın KENDİ objesi + istenen id'nin echo'su
        return httpx.Response(200, json={**UUID_DB[own_id], "requested": oid})

    store, oracle, A, B, ep = _uuid_setup(handler)
    f = await oracle.run(ep, A, B, resource_key="order")
    assert f.verdict != base.CONFIRMED, "echo'lanan obje id'si kanıt sayıldı (FP)"
    assert VICTIM_UUID not in f.evidence.leaked_markers
    await store.aclose_all()


@pytest.mark.asyncio
async def test_learner_confirms_leak_under_unknown_field_name():
    # Gerçek sızıntı: kurbanın özel verisi "beneficiaryRef" gibi listede OLMAYAN bir alanda.
    secret = "ref9c3a7b1d4e8f2a6b"
    db = {
        VICTIM_UUID: {"orderId": VICTIM_UUID, "beneficiaryRef": secret},
        ATTACKER_UUID: {"orderId": ATTACKER_UUID, "beneficiaryRef": "ref0000000000000000"},
    }

    def handler(request):
        oid = request.url.path.rsplit("/", 1)[-1]
        if oid not in db:
            return httpx.Response(404, json={"error": "not found"})
        return httpx.Response(200, json=db[oid])      # ownership YOK → gerçek IDOR

    store, oracle, A, B, ep = _uuid_setup(handler)
    f = await oracle.run(ep, A, B, resource_key="order")
    assert f.verdict == base.CONFIRMED
    assert secret in f.evidence.leaked_markers
    # Obje id'si kanıt sayılmamalı (saldırgan gönderdi)
    assert VICTIM_UUID not in f.evidence.leaked_markers
    await store.aclose_all()
