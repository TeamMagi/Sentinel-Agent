"""Scanner — kapsam-dışı/denied endpoint dayanıklılığı (bug düzeltmesi).

Recon bazen kapsam dışı ya da denied (ör. /createdb) bir endpoint keşfeder. O endpoint'e
giden replay `ScopeError` fırlatır (scope kapısı — invariant §5.6). Eskiden bu istisna TÜM
dispatch döngüsünü çökertiyordu; artık ilgili hipotez atlanır ve tarama devam eder.
"""
import httpx
import pytest

from pentestai.models import Actor, AuthState, BudgetConfig, Endpoint, Hypothesis, Scope
from pentestai.net import SessionStore
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"
ORDERS = {
    "A-100": {"id": "A-100", "owner": "user_A", "email": "alice@test.local"},
    "B-200": {"id": "B-200", "owner": "user_B", "email": "bob@test.local"},
}


def handler(request):
    oid = request.url.path.rsplit("/", 1)[-1]
    return httpx.Response(200, json=ORDERS[oid]) if oid in ORDERS else httpx.Response(404, json={})


@pytest.mark.asyncio
async def test_out_of_scope_hypothesis_does_not_crash_scan(tmp_path):
    # scope yalnızca /api/ önekine izin verir → /secret/dump kapsam dışıdır (authorize Deny).
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/api/"])
    scanner = Scanner(BASE, scope, BudgetConfig(max_rps_per_host=1000), out_dir=str(tmp_path))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    A = store.create(Actor(name="user_A", role="user",
                           auth=AuthState(headers={"Authorization": "Bearer A"}),
                           own_object_ids={"orders": "A-100"}))
    B = store.create(Actor(name="user_B", role="user",
                           auth=AuthState(headers={"Authorization": "Bearer B"}),
                           own_object_ids={"orders": "B-200"}))

    out_of_scope = Hypothesis(type="excessive_data_exposure",
                              endpoint=Endpoint(method="GET", path_template="/secret/dump"))
    in_scope = Hypothesis(type="idor",
                          endpoint=Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id"))

    # kapsam-dışı ÖNCE gelir: eskiden ScopeError buradan itibaren her şeyi çökertirdi.
    findings = await scanner.run_hypotheses([A, B], [out_of_scope, in_scope])

    # çökme yok + in-scope IDOR yine CONFIRMED bulunur.
    assert any(f.verdict == "CONFIRMED" and f.type == "idor" for f in findings), \
        "kapsam-dışı hipoteze rağmen in-scope IDOR CONFIRMED bulunmalı"
    await scanner.aclose()
