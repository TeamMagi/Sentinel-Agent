"""Scanner — daha önce test edilmemiş dallar: recon yardımcıları (discover_more/GraphQL BOLA/
session-lifecycle/template scan), run_hypotheses'ın az-kullanılan tipleri (unauthorized_access/
continue dalları/file_upload/excessive_data_exposure id'siz), dry_run/passive ve run_recon_scan'in
opsiyonel bayrak kapıları (enumerate_more/login_url/logout_url/template_scan/enrich/triage_fp).

Ağsız: tüm HTTP `httpx.MockTransport` üzerinden — gerçek ağa/Docker'a hiç gidilmez.
"""
import pathlib

import httpx
import pytest

from pentestai.models import Actor, AuthState, BudgetConfig, Endpoint, Hypothesis, Scope
from pentestai.net import SessionStore
from pentestai.scanner import Scanner

BASE = "http://localhost:3000"
REPO_TEMPLATES = pathlib.Path(__file__).resolve().parents[1] / "templates"


class _FakeLLM:
    """FindingEnricher/FpTriager için sahte LLM — her iki şemayı da (fazla alan pydantic'te
    yok sayılır) karşılayan tek bir JSON döner; gerçek ağa çıkmaz."""

    async def complete(self, system: str, user: str, *, fmt=None) -> str:
        return ('{"severity":"Medium","impact":"etki","remediation":"öneri",'
                '"triage_note":"not","likely_fp":false,"reason":"neden"}')


# --- Scanner.__init__ ---

def test_scanner_init_with_enum_users_registers_detector():
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000])
    scanner = Scanner(BASE, scope, BudgetConfig(max_rps_per_host=1000),
                      enum_users=("valid@test.local", "ghost@test.local"))
    assert "user_enumeration" in scanner.detectors


# --- discover_more + _run_graphql_bola (RK-3/RK-8 uçtan uca) ---

GQL_SCHEMA = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "types": [
                {"name": "Query", "kind": "OBJECT",
                 "fields": [{"name": "order", "args": [{"name": "id"}]}]},
            ],
        }
    }
}


def _discover_handler(request):
    if request.url.path.startswith("/graphql"):
        return httpx.Response(200, json=GQL_SCHEMA)
    return httpx.Response(404, json={})


@pytest.mark.asyncio
async def test_discover_more_runs_wordlist_graphql_introspection_and_provider_adapters():
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000])
    scanner = Scanner(BASE, scope, BudgetConfig(max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(_discover_handler))
    A = store.create(Actor(name="user_A", role="user", auth=AuthState(headers={"Authorization": "Bearer A"}),
                           own_object_ids={"order": "1"}))
    B = store.create(Actor(name="user_B", role="user", auth=AuthState(headers={"Authorization": "Bearer B"})))

    extra, findings = await scanner.discover_more(A, [], sessions=[A, B])

    assert isinstance(extra, list)                                    # wordlist + provider katkısı (burada boş)
    assert any(f.type == "graphql_introspection" for f in findings)    # introspection açık → bilgi ifşası
    assert any(f.type == "graphql_bola" for f in findings)             # RK-3: BOLA adayı GERÇEKTEN koşuldu

    await store.aclose_all()


# --- run_session_lifecycle_scan ---

@pytest.mark.asyncio
async def test_run_session_lifecycle_scan_direct():
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000])
    scanner = Scanner(BASE, scope, BudgetConfig(max_rps_per_host=1000))

    def handler(request):
        if request.url.path == "/logout":
            return httpx.Response(200, json={})
        return httpx.Response(200, json={"id": "1"})

    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    A = store.create(Actor(name="user_A", role="user", auth=AuthState(headers={"Authorization": "Bearer A"}),
                           own_object_ids={"orders": "1"}))
    endpoints = [Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id")]

    findings = await scanner.run_session_lifecycle_scan(A, logout_url=BASE + "/logout", endpoints=endpoints)
    assert isinstance(findings, list)   # logout-invalidation + JWT exp claim kontrolü çöküşsüz koştu

    await store.aclose_all()


# --- run_template_scan ---

@pytest.mark.asyncio
async def test_run_template_scan_without_detector_returns_empty():
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000])
    scanner = Scanner(BASE, scope, BudgetConfig(max_rps_per_host=1000))   # templates_dir verilmedi
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(lambda r: httpx.Response(404, json={})))
    A = store.create(Actor(name="user_A", role="user", auth=AuthState(headers={"Authorization": "Bearer A"})))

    assert await scanner.run_template_scan(A) == []
    await store.aclose_all()


@pytest.mark.asyncio
async def test_run_template_scan_with_templates_dir_runs_real_detector():
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000])
    scanner = Scanner(BASE, scope, BudgetConfig(max_rps_per_host=1000), templates_dir=str(REPO_TEMPLATES))
    assert scanner.template_detector is not None
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(lambda r: httpx.Response(404, json={})))
    A = store.create(Actor(name="user_A", role="user", auth=AuthState(headers={"Authorization": "Bearer A"})))

    findings = await scanner.run_template_scan(A)
    assert isinstance(findings, list)   # gerçek repo template'leriyle çöküşsüz koştu (eşleşme yok → [])

    await store.aclose_all()


# --- run_rate_limit_scan: login/register dalları ---

@pytest.mark.asyncio
async def test_run_rate_limit_scan_login_and_register_branches():
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_methods=["GET", "HEAD", "POST"])
    scanner = Scanner(BASE, scope, BudgetConfig(max_rps_per_host=1000))

    def handler(request):
        if request.url.path == "/login":
            return httpx.Response(401, json={"error": "invalid"})
        if request.url.path == "/register":
            return httpx.Response(400, json={"error": "weak password"})
        return httpx.Response(200, json={"id": "1"})

    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    A = store.create(Actor(name="user_A", role="user", auth=AuthState(headers={"Authorization": "Bearer A"}),
                           own_object_ids={"orders": "1"}))
    endpoints = [Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id")]

    findings = await scanner.run_rate_limit_scan(
        A, endpoints, login_url=BASE + "/login", register_url=BASE + "/register")
    assert isinstance(findings, list)   # burst + brute-force + zayıf-şifre dalları çöküşsüz koştu

    await store.aclose_all()


# --- run_hypotheses: unauthorized_access (self.anon gerekir — daha önce hiç tetiklenmemiş) ---

@pytest.mark.asyncio
async def test_run_hypotheses_unauthorized_access_with_and_without_id():
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000])
    scanner = Scanner(BASE, scope, BudgetConfig(max_rps_per_host=1000))

    def handler(request):
        if "authorization" in {k.lower() for k in request.headers}:
            return httpx.Response(200, json={"id": "1"})
        return httpx.Response(401, json={"error": "auth required"})

    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    A = store.create(Actor(name="user_A", role="user", auth=AuthState(headers={"Authorization": "Bearer A"}),
                           own_object_ids={"orders": "1"}))
    scanner.anon = store.create(Actor(name="anonymous", role="anonymous"))

    hyps = [
        Hypothesis(type="unauthorized_access",
                  endpoint=Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id"),
                  rationale="r"),
        Hypothesis(type="unauthorized_access",
                  endpoint=Endpoint(method="GET", path_template="/api/orders"),
                  rationale="r"),
    ]
    findings = await scanner.run_hypotheses([A], hyps)

    assert len(findings) == 2   # id'li (sahiplik eşleşti) + id'siz (targets[:1] tek sefer)
    assert all(f.type == "unauthorized_access" for f in findings)
    assert all(f.found_as == "anonymous" and f.victim_as == "user_A" for f in findings)
    assert scanner._roles.get("anonymous") == "anonymous"   # self.anon rol haritasına da işlendi

    await store.aclose_all()


# --- run_hypotheses: sahiplenmeyen aktör 'continue' ile atlanır (state_change/method_bypass/
# csrf/mass_assignment/stored_xss) + file_upload (koşulsuz, sessions[0]) ---

@pytest.mark.asyncio
async def test_run_hypotheses_skips_non_owning_actor_and_runs_file_upload():
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000],
                  allowed_methods=["GET", "HEAD", "PUT", "POST"], destructive_tests=True)
    scanner = Scanner(BASE, scope, BudgetConfig(max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(
        lambda r: httpx.Response(200, json={"id": "1"})))
    owner = store.create(Actor(name="owner", role="user", auth=AuthState(headers={"Authorization": "Bearer O"}),
                               own_object_ids={"orders": "1"}))
    outsider = store.create(Actor(name="outsider", role="user", auth=AuthState(headers={"Authorization": "Bearer X"})))

    ep_put = Endpoint(method="PUT", path_template="/api/orders/{id}", id_param="id")
    ep_upload = Endpoint(method="POST", path_template="/api/upload")
    hyps = [
        Hypothesis(type="state_change_authz", endpoint=ep_put, rationale="r"),
        Hypothesis(type="method_bypass", endpoint=ep_put, rationale="r"),
        Hypothesis(type="csrf", endpoint=ep_put, rationale="r"),
        Hypothesis(type="mass_assignment", endpoint=ep_put, rationale="r"),
        Hypothesis(type="stored_xss", endpoint=ep_put, rationale="r"),
        Hypothesis(type="file_upload", endpoint=ep_upload, rationale="r"),
    ]
    findings = await scanner.run_hypotheses([owner, outsider], hyps)
    by_type: dict[str, list] = {}
    for f in findings:
        by_type.setdefault(f.type, []).append(f)

    # 'outsider' kaynağı sahiplenmiyor → 'continue' ile atlanır, yalnızca 'owner' kurban olabilir.
    for t in ("state_change_authz", "method_bypass", "csrf", "mass_assignment", "stored_xss"):
        assert by_type[t], f"{t} bulgusu üretilmedi"
        assert all(f.victim == "owner" for f in by_type[t])
    assert len(by_type["file_upload"]) == 1   # koşulsuz, yalnızca sessions[0] ile bir kez

    await store.aclose_all()


@pytest.mark.asyncio
async def test_run_hypotheses_excessive_data_exposure_without_id_uses_single_target():
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000])
    scanner = Scanner(BASE, scope, BudgetConfig(max_rps_per_host=1000))
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(
        lambda r: httpx.Response(200, json=[{"id": "1"}])))
    A = store.create(Actor(name="user_A", role="user", auth=AuthState(headers={"Authorization": "Bearer A"})))
    B = store.create(Actor(name="user_B", role="user", auth=AuthState(headers={"Authorization": "Bearer B"})))

    ep = Endpoint(method="GET", path_template="/api/orders")   # id'siz koleksiyon → has_id=False
    hyp = Hypothesis(type="excessive_data_exposure", endpoint=ep, rationale="r")
    findings = await scanner.run_hypotheses([A, B], [hyp])

    assert len(findings) == 1                 # id'siz koleksiyon → targets[:1], tek sefer yeter
    assert findings[0].victim == "user_A"      # ilk aktörle test edildi

    await store.aclose_all()


# --- dry_run / passive (network yok; policy.authorize saf) ---

def test_dry_run_prints_allow_and_deny(capsys):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/api"])
    scanner = Scanner(BASE, scope, BudgetConfig(max_rps_per_host=1000))
    actor = Actor(name="user_A", role="user", own_object_ids={"orders": "1"})
    endpoints = [
        Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id"),      # scope içi → ALLOW
        Endpoint(method="GET", path_template="/outside/orders/{id}", id_param="id"),  # scope dışı → DENY
    ]
    scanner.dry_run([(actor, {})], endpoints)
    out = capsys.readouterr().out
    assert "[ALLOW]" in out
    assert "[DENY:" in out


def test_passive_prints_endpoints(capsys):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000])
    scanner = Scanner(BASE, scope, BudgetConfig(max_rps_per_host=1000))
    endpoints = [Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id")]
    scanner.passive(endpoints)
    out = capsys.readouterr().out
    assert "/api/orders/{id}" in out
    assert "resource=orders" in out


# --- run_recon_scan: opsiyonel bayrak kapıları (enumerate_more/login_url/logout_url/
# template_scan/enrich/triage_fp) — hepsi tek koşumda, gerçek alt-metotlarla (mock yok) ---

@pytest.mark.asyncio
async def test_run_recon_scan_exercises_all_optional_gates():
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000],
                  allowed_methods=["GET", "HEAD", "POST"])
    scanner = Scanner(BASE, scope, BudgetConfig(max_rps_per_host=1000),
                      llm=_FakeLLM(), templates_dir=str(REPO_TEMPLATES))

    def handler(request):
        path = request.url.path
        if path == "/login":
            return httpx.Response(401, json={"error": "invalid"})
        if path == "/register":
            return httpx.Response(400, json={"error": "weak password"})
        if path == "/logout":
            return httpx.Response(200, json={})
        if path == "/rest/user/whoami":
            return httpx.Response(200, json={"cartId": "7"})   # R-B3 scalar-inference tetiklenir
        if path.startswith("/api/orders/"):
            return httpx.Response(200, json={"id": path.rsplit("/", 1)[-1]})
        if path == "/api/orders":
            return httpx.Response(200, json=[{"id": "1"}])
        return httpx.Response(404, json={})

    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    A = store.create(Actor(name="user_A", role="user", auth=AuthState(headers={"Authorization": "Bearer A"}),
                           own_object_ids={"orders": "1"}))
    endpoints = [Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id")]

    findings = await scanner.run_recon_scan(
        [A], endpoints,
        enumerate_more=True, login_url=BASE + "/login", register_url=BASE + "/register",
        logout_url=BASE + "/logout", enrich=True, triage_fp=True,
    )
    assert isinstance(findings, list) and findings   # çöküşsüz koştu, en az bir bulgu üretti
    # crawl.feedback_bootstrap → infer_resource_ids → own_object_ids'e 'cart' eklendi (R-B3).
    assert A.actor.own_object_ids.get("cart") == "7"
    # enrich=True + llm verildi → en az bir bulguya LLM açıklaması işlendi.
    assert any(f.impact == "etki" for f in findings if f.verdict != "REJECTED")

    await store.aclose_all()
