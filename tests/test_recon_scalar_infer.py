"""Scalar inference / feedback-driven keşif (R-B3). Network yok.

infer_resource_ids: yanıt gövdesinden {kaynak: id} ilişkisi. CrawlRecon.feedback_bootstrap:
whoami/profile gezerek own_object_ids'i ELLE vermeden doldurur.
"""
import httpx
import pytest

from pentestai.models import Actor, AuthState, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.orchestrator.idtools import infer_resource_ids
from pentestai.policy import PolicyEngine
from pentestai.recon.crawl import CrawlRecon

BASE = "http://localhost:3000"


def test_infer_from_suffix_keys_and_nested_id():
    body = {
        "user": {"id": 4, "email": "alice@test.local"},   # nested bare id → user=4
        "basketId": 7,                                     # <ad>Id → basket=7
        "recent_order_id": "O-9",                          # <ad>_id → recent_order=O-9
        "paid": True, "valid": False,                      # 'id' ile biten TUZAK değil (bool/lowercase)
    }
    out = infer_resource_ids(body)
    assert out["user"] == "4"
    assert out["basket"] == "7"
    assert out["recent_order"] == "O-9"
    assert "paid" not in out and "valid" not in out


def test_infer_ignores_bare_top_level_id():
    assert infer_resource_ids({"id": 1, "name": "x"}) == {}   # bağlamsız düz id atlanır


@pytest.mark.asyncio
async def test_feedback_bootstrap_discovers_ids_without_config():
    def handler(request):
        if request.url.path == "/rest/user/whoami":
            return httpx.Response(200, json={"user": {"id": "U-42", "email": "alice@test.local"},
                                             "basketId": "BSK-7"})
        return httpx.Response(404, json={"error": "not found"})

    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    s = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer A"})))
    found = await CrawlRecon(Replayer(PolicyEngine(scope)), BASE).feedback_bootstrap(s)
    await store.aclose_all()
    assert found["user"] == "U-42"     # whoami gövdesinden elle verilmeden bulundu
    assert found["basket"] == "BSK-7"
