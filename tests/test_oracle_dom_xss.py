"""DomXssOracle — TIER_C.md C1: query/hash → istemci-taraflı sink → gerçek tarayıcıda JS-çalıştırma
kanıtı. Network'süz (CLAUDE.md §6): sahte origin `context.route()` ile TAMAMEN yerelden sunulur.
"""
import httpx
import pytest
import pytest_asyncio
from playwright.async_api import async_playwright

from pentestai.browser.driver import BrowserDriver
from pentestai.models import Actor, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import base
from pentestai.oracle.dom_xss import DomXssOracle
from pentestai.policy import PolicyEngine

ORIGIN = "https://dom.test.local"
EP = Endpoint(method="GET", path_template="/items/{id}", id_param="id")

# Sunucu HANGİ path/query ile çağrılırsa çağrılsın AYNI SPA kabuğunu döner — gerçek DOM XSS
# uygulamalarının tipik şekli (yönlendirme istemci tarafında). Zafiyet, `sink` innerHTML mi
# textContent mi olduğuna göre var/yok olur.
_PAGE = """
<html><body>
  <div id="out"></div>
  <script>
    function dec(v) { try { return decodeURIComponent(v); } catch (e) { return v; } }
    var out = document.getElementById('out');
    // query: DomXssOracle "?param=<payload>" biçiminde ekler — değeri "=" SONRASINDAN al.
    var q = location.search.slice(1);
    if (q) { var eq = q.indexOf('='); out.__QSINK__ += dec(eq >= 0 ? q.slice(eq + 1) : q); }
    // hash: DomXssOracle "#<payload>" biçiminde ekler (anahtar YOK, ham) — olduğu gibi al.
    var h = location.hash.slice(1);
    if (h) out.__HSINK__ += dec(h);
  </script>
</body></html>
"""


def _page(*, query_vulnerable: bool, hash_vulnerable: bool) -> str:
    return (_PAGE
            .replace("__QSINK__", "innerHTML" if query_vulnerable else "textContent")
            .replace("__HSINK__", "innerHTML" if hash_vulnerable else "textContent"))


async def _serve(route, html: str) -> None:
    await route.fulfill(status=200, content_type="text/html", body=html)


@pytest_asyncio.fixture
async def browser():
    async with async_playwright() as pw:
        b = await pw.chromium.launch()
        yield b
        await b.close()


@pytest_asyncio.fixture
async def context(browser):
    ctx = await browser.new_context()
    yield ctx
    await ctx.close()


def _setup(context):
    scope = Scope(allowed_hosts=["dom.test.local"], allowed_ports=[443],
                  allowed_path_prefixes=["/"], allowed_methods=["GET"])
    policy = PolicyEngine(scope)
    driver = BrowserDriver(policy=policy, context=context, timeout_ms=5_000, settle_ms=150)
    replayer = Replayer(policy)   # oracle içinde asla .replay() çağrılmaz — tarayıcı kendi ağını kullanır
    oracle = DomXssOracle(replayer, ORIGIN, browser_driver=driver)
    store = SessionStore(transport=httpx.MockTransport(lambda r: httpx.Response(404)))
    A = Actor(name="user_A", own_object_ids={"items": "42"})
    return oracle, store, store.create(A)


@pytest.mark.asyncio
async def test_confirmed_via_query_sink(context):
    await context.route(f"{ORIGIN}/**",
                        lambda r: _serve(r, _page(query_vulnerable=True, hash_vulnerable=False)))
    oracle, store, A = _setup(context)
    f = await oracle.run(EP, A, A, resource_key="items", finding_id="F-1")
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert f.evidence.leaked_markers and "query" in f.evidence.leaked_markers[0]
    await store.aclose_all()


@pytest.mark.asyncio
async def test_confirmed_via_hash_only_sink(context):
    """query GÜVENLİ (textContent), yalnızca hash innerHTML'e yazıyor — SAF DOM XSS: payload
    sunucuya hiç GİTMEDİĞİ halde (URL fragment) yine CONFIRMED (differential kontrol geçer)."""
    await context.route(f"{ORIGIN}/**",
                        lambda r: _serve(r, _page(query_vulnerable=False, hash_vulnerable=True)))
    oracle, store, A = _setup(context)
    f = await oracle.run(EP, A, A, resource_key="items", finding_id="F-1")
    assert f.verdict == base.CONFIRMED
    assert "hash" in f.evidence.leaked_markers[0]
    await store.aclose_all()


@pytest.mark.asyncio
async def test_rejected_when_fully_escaped(context):
    await context.route(f"{ORIGIN}/**",
                        lambda r: _serve(r, _page(query_vulnerable=False, hash_vulnerable=False)))
    oracle, store, A = _setup(context)
    f = await oracle.run(EP, A, A, resource_key="items", finding_id="F-1")
    assert f.verdict == base.REJECTED
    assert not f.evidence.leaked_markers
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_for_non_get_method(context):
    oracle, store, A = _setup(context)
    post_ep = Endpoint(method="POST", path_template="/items/{id}", id_param="id")
    f = await oracle.run(post_ep, A, A, resource_key="items", finding_id="F-1")
    assert f.verdict == base.INCONCLUSIVE
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_when_victim_id_missing(context):
    oracle, store, A = _setup(context)
    A.actor.own_object_ids.clear()
    f = await oracle.run(EP, A, A, resource_key="items", finding_id="F-1")
    assert f.verdict == base.INCONCLUSIVE
    await store.aclose_all()
