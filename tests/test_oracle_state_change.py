"""StateChangingOracle — yazma/silme yetki testi (v1). DESIGN.md §14.

Sahte durumlu uygulama (MockTransport): vulnerable → saldırgan kurbanın objesini siler/değiştirir
(CONFIRMED, kalıcı mutasyon kanıtı); secure → ownership check 403 döner (REJECTED).

destructive_tests bayrağının PolicyEngine.authorize'a bağlanması: bkz. test_authorize.py
(test_deny_destructive_when_flag_off / test_allow_destructive_when_flag_on). Burada scope,
yazma method'larına izin verecek + destructive_tests=true şekilde kurulur.
"""
import json

import httpx
import pytest

from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import base
from pentestai.oracle.canary import CanaryPlanter
from pentestai.oracle.state_change import StateChangingOracle
from pentestai.policy import PolicyEngine

TOKEN_ACTOR = {"TOKEN_A": "user_A", "TOKEN_B": "user_B"}
BASE = "http://localhost:3000"


def _id_of(request):
    return request.url.path.rsplit("/", 1)[-1]


def _actor_of(request):
    return TOKEN_ACTOR.get(request.headers.get("authorization", "").replace("Bearer ", ""))


def make_app(secure: bool):
    """Durumlu sahte API: GET/PUT/DELETE + opsiyonel ownership kontrolü."""
    db = {
        "A-1": {"id": "A-1", "owner": "user_A", "quantity": 1},
        "B-2": {"id": "B-2", "owner": "user_B", "quantity": 1},
    }

    def handler(request):
        oid = _id_of(request)
        actor = _actor_of(request)
        method = request.method.upper()
        obj = db.get(oid)

        if method == "GET":
            if obj is None:
                return httpx.Response(404, json={"error": "not found"})
            return httpx.Response(200, json=obj)

        # state-changing: obje yoksa 404 (negative control bunu bekler)
        if obj is None:
            return httpx.Response(404, json={"error": "not found"})
        if secure and obj["owner"] != actor:
            return httpx.Response(403, json={"error": "forbidden"})

        if method == "DELETE":
            db.pop(oid, None)
            return httpx.Response(200, json={"status": "success"})
        if method in ("PUT", "PATCH"):
            body = json.loads(request.content or b"{}")
            obj.update(body)                       # ownership check YOK (vulnerable) → mutasyon geçer
            return httpx.Response(200, json=obj)
        return httpx.Response(405, json={"error": "method"})

    return handler


def _setup(handler, method, *, use_canary=False):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["GET", "PUT", "PATCH", "DELETE"], destructive_tests=True)
    store = SessionStore(transport=httpx.MockTransport(handler))
    A = Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer TOKEN_A"}),
              own_object_ids={"order": "A-1"})
    B = Actor(name="user_B", auth=AuthState(headers={"Authorization": "Bearer TOKEN_B"}),
              own_object_ids={"order": "B-2"})
    endpoint = Endpoint(method=method, path_template="/api/orders/{id}", id_param="id")
    replayer = Replayer(PolicyEngine(scope))
    planter = CanaryPlanter(replayer, BASE) if use_canary else None
    oracle = StateChangingOracle(replayer, BASE, canary_planter=planter)
    return store, oracle, endpoint, store.create(A), store.create(B)


def make_restore_failing_app():
    """PUT vulnerable (ownership check yok) ama kurbanın objesine YAPILAN İKİNCİ yazma
    (RK-1'in restore denemesi) 500 döner — güvenli-yazma döngüsünün 'yarıda kaldı' yolunu
    tetikler: saldırı kalıcı mutasyon olarak CONFIRMED olur ama geri alma başarısız kalır."""
    db = {
        "A-1": {"id": "A-1", "owner": "user_A", "quantity": 1},
        "B-2": {"id": "B-2", "owner": "user_B", "quantity": 1},
    }
    writes_to_a1 = {"count": 0}

    def handler(request):
        oid = _id_of(request)
        method = request.method.upper()
        obj = db.get(oid)
        if method == "GET":
            if obj is None:
                return httpx.Response(404, json={"error": "not found"})
            return httpx.Response(200, json=obj)
        if obj is None:
            return httpx.Response(404, json={"error": "not found"})
        if method == "PUT":
            if oid == "A-1":
                writes_to_a1["count"] += 1
                if writes_to_a1["count"] == 2:      # 1. yazma = saldırı, 2. yazma = geri alma
                    return httpx.Response(500, json={"error": "boom"})
            body = json.loads(request.content or b"{}")
            obj.update(body)
            return httpx.Response(200, json=obj)
        return httpx.Response(405, json={"error": "method"})

    return handler


@pytest.mark.asyncio
async def test_confirmed_delete_on_vulnerable():
    store, oracle, ep, A, B = _setup(make_app(secure=False), "DELETE")
    f = await oracle.run(ep, A, B, resource_key="order")   # victim=A, attacker=B
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert f.evidence.positive_control and f.evidence.negative_control and f.evidence.baseline_stable
    assert f.evidence.leaked_markers            # kalıcı silme kanıtı
    assert "-X DELETE" in f.evidence.repro_curl
    # RK-1: silme otomatik geri alınamaz — operatör için recovery_state kaydedilir.
    assert f.evidence.restored is False
    assert f.evidence.recovery_state is not None
    assert f.evidence.recovery_state["resource_id"] == "A-1"
    assert f.evidence.recovery_state["victim"] == "user_A"
    await store.aclose_all()


@pytest.mark.asyncio
async def test_rejected_delete_on_secure():
    store, oracle, ep, A, B = _setup(make_app(secure=True), "DELETE")
    f = await oracle.run(ep, A, B, resource_key="order")
    assert f.verdict == base.REJECTED
    await store.aclose_all()


@pytest.mark.asyncio
async def test_confirmed_put_persisted_mutation():
    store, oracle, ep, A, B = _setup(make_app(secure=False), "PUT")
    f = await oracle.run(ep, A, B, resource_key="order")
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert any("8931" in m for m in f.evidence.leaked_markers)   # sentinel kurbanın objesine yazıldı
    await store.aclose_all()


@pytest.mark.asyncio
async def test_confirmed_put_restores_victim_object():
    # RK-1: mutasyon doğrulandıktan SONRA kurbanın objesi kendi session'ıyla eski haline
    # döndürülür ve geri alma bizzat okunarak doğrulanır.
    store, oracle, ep, A, B = _setup(make_app(secure=False), "PUT")
    f = await oracle.run(ep, A, B, resource_key="order")
    assert f.verdict == base.CONFIRMED
    assert f.evidence.restored is True
    assert f.evidence.recovery_state is None
    # gerçekten geri alındığını objeyi tekrar okuyarak doğrula.
    after_restore = await oracle.replayer.replay(oracle._read_req(ep, "A-1"), A)
    assert after_restore.json_body["quantity"] == 1
    await store.aclose_all()


@pytest.mark.asyncio
async def test_put_restore_failure_records_recovery_state():
    # RK-1: saldırı CONFIRMED olur ama geri-alma yazması 500 ile başarısız olursa — verdict
    # yine kod tarafından belirlenmiş kalır, yalnızca recovery_state operatöre kurtarma verisi taşır.
    store, oracle, ep, A, B = _setup(make_restore_failing_app(), "PUT")
    f = await oracle.run(ep, A, B, resource_key="order")
    assert f.verdict == base.CONFIRMED
    assert f.evidence.restored is False
    assert f.evidence.recovery_state is not None
    assert f.evidence.recovery_state["field"] == "quantity"
    assert f.evidence.recovery_state["original_value"] == 1
    await store.aclose_all()


@pytest.mark.asyncio
async def test_put_uses_canary_planter_value_when_given():
    # RK-1: canary_planter enjekte edilirse sabit "8931" yerine CanaryPlanter'ın paylaşılan
    # rastgele/tahmin edilemez değer şeması kullanılır — hem sentinel yazımında hem kanıtta.
    store, oracle, ep, A, B = _setup(make_app(secure=False), "PUT", use_canary=True)
    f = await oracle.run(ep, A, B, resource_key="order")
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert any(m.startswith("kalıcı mutasyon:") and "snt-canary-" in m for m in f.evidence.leaked_markers)
    assert not any("8931" in m for m in f.evidence.leaked_markers)
    await store.aclose_all()


@pytest.mark.asyncio
async def test_rejected_put_on_secure():
    store, oracle, ep, A, B = _setup(make_app(secure=True), "PUT")
    f = await oracle.run(ep, A, B, resource_key="order")
    assert f.verdict == base.REJECTED
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_when_destructive_tests_disabled():
    # policy kapısı destructive_tests=False'ta yıkıcı isteği reddeder → oracle sessizce
    # yanlış yargı vermek yerine INCONCLUSIVE döner (§5.4).
    store, oracle, ep, A, B = _setup(make_app(secure=False), "DELETE")
    oracle.replayer.policy.scope = oracle.replayer.policy.scope.model_copy(
        update={"destructive_tests": False})
    f = await oracle.run(ep, A, B, resource_key="order")
    assert f.verdict == base.INCONCLUSIVE
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_when_victim_id_missing():
    store, oracle, ep, A, B = _setup(make_app(secure=False), "DELETE")
    A.actor.own_object_ids.clear()               # kurbanın kendi id'si yok
    f = await oracle.run(ep, A, B, resource_key="order")
    assert f.verdict == base.INCONCLUSIVE
    await store.aclose_all()
