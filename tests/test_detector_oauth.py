"""OAuth/OIDC yanlış yapılandırma dedektörü — gevşek redirect_uri / state eksikliği.

Sahte authorize endpoint'i; kanıt = saldırgan redirect_uri'ye yönlendirme (Location host).
Network yok: httpx.MockTransport.
"""
import httpx
import pytest

from pentestai.detector.oauth import OAuthDetector
from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import base
from pentestai.policy import PolicyEngine

AUTHZ = Endpoint(method="GET", path_template="/oauth/authorize", id_location="query")
BASE = "http://localhost:3000"


def _setup(handler):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    s = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer A"})))
    return store, OAuthDetector(Replayer(PolicyEngine(scope)), BASE), s


async def _run(handler, endpoint=AUTHZ):
    store, det, s = _setup(handler)
    fs = await det.run(endpoint, s)
    await store.aclose_all()
    return fs


def oauth_vuln(request):
    """redirect_uri'yi doğrulamadan oraya yönlendiren açık authorize endpoint'i."""
    ru = request.url.params.get("redirect_uri", "")
    if ru:
        return httpx.Response(302, headers={"location": f"{ru}?code=abc123"})
    return httpx.Response(400, text="missing redirect_uri")


def oauth_safe(request):
    """redirect_uri'yi allowlist'e göre doğrular; state'i zorunlu kılar."""
    ru = request.url.params.get("redirect_uri", "")
    if "client.example" not in ru:
        return httpx.Response(400, text="redirect_uri not allowed")
    if not request.url.params.get("state"):
        return httpx.Response(400, text="state parameter required")
    return httpx.Response(302, headers={"location": f"{ru}?code=ok"})


def oauth_nostate(request):
    """redirect_uri doğru doğrulanıyor ama state zorlanmıyor → LIKELY."""
    ru = request.url.params.get("redirect_uri", "")
    if "client.example" not in ru:
        return httpx.Response(400, text="redirect_uri not allowed")
    return httpx.Response(302, headers={"location": f"{ru}?code=ok"})


@pytest.mark.asyncio
async def test_oauth_confirmed_loose_redirect_uri():
    fs = await _run(oauth_vuln)
    f = fs[0]
    assert f.type == "oauth_misconfig"
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert f.evidence.leaked_markers


@pytest.mark.asyncio
async def test_oauth_rejected_when_validated_and_state_enforced():
    fs = await _run(oauth_safe)
    assert fs[0].verdict == base.REJECTED


@pytest.mark.asyncio
async def test_oauth_likely_when_state_not_enforced():
    fs = await _run(oauth_nostate)
    assert fs[0].verdict == base.LIKELY


@pytest.mark.asyncio
async def test_oauth_skipped_on_non_authorize_endpoint():
    # authorize endpoint'i olmayan bir path'te gürültü üretme (guard → REJECTED, istek atmaz).
    ep = Endpoint(method="GET", path_template="/rest/basket", id_location="query")
    fs = await _run(lambda r: httpx.Response(302, headers={"location": "https://evil.example/x"}), ep)
    assert fs[0].verdict == base.REJECTED
