"""BrowserDriver — TIER_C.md C1: gerçek tarayıcıda JS-çalıştırma kanıtı toplayan yeni motor.

Network'süz (CLAUDE.md §6): gerçek bir hedefe gidilmez. Sahte bir origin
(`https://dom.test.local`) `BrowserContext.route()` ile TAMAMEN yerelden sunulur —
`httpx.MockTransport`'un Playwright karşılığı (aynı desen `tests/test_auth_browser.py`'de).
"""
import pytest
import pytest_asyncio
from playwright.async_api import async_playwright

from pentestai.browser.driver import BrowserDriver
from pentestai.models import AuthState, Scope
from pentestai.net.limits import BudgetExceeded, BudgetTracker
from pentestai.net.replay import ScopeError
from pentestai.policy import PolicyEngine

ORIGIN = "https://dom.test.local"

BINDING_PAGE = "<html><body><script>window.__sentinelReport('MARKER');</script></body></html>"
DIALOG_PAGE = "<html><body><script>alert('MARKER');</script></body></html>"
INERT_PAGE = "<html><body>nothing here</body></html>"
COOKIE_ECHO_PAGE = "<html><body><script>window.__sentinelReport(document.cookie);</script></body></html>"


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


@pytest.mark.asyncio
async def test_binding_callback_proves_execution(context):
    await context.route(f"{ORIGIN}/x", lambda r: _serve(r, BINDING_PAGE))
    driver = BrowserDriver(context=context, timeout_ms=5_000, settle_ms=100)
    ev = await driver.navigate_and_observe(f"{ORIGIN}/x", marker="MARKER")
    assert ev.executed is True
    assert ev.channel == "binding"
    assert ev.status == 200


@pytest.mark.asyncio
async def test_dialog_proves_execution(context):
    await context.route(f"{ORIGIN}/x", lambda r: _serve(r, DIALOG_PAGE))
    driver = BrowserDriver(context=context, timeout_ms=5_000, settle_ms=100)
    ev = await driver.navigate_and_observe(f"{ORIGIN}/x", marker="MARKER")
    assert ev.executed is True
    assert ev.channel == "dialog"


@pytest.mark.asyncio
async def test_inert_page_does_not_report_execution(context):
    await context.route(f"{ORIGIN}/x", lambda r: _serve(r, INERT_PAGE))
    driver = BrowserDriver(context=context, timeout_ms=5_000, settle_ms=100)
    ev = await driver.navigate_and_observe(f"{ORIGIN}/x", marker="MARKER")
    assert ev.executed is False
    assert ev.channel is None
    assert ev.status == 200


@pytest.mark.asyncio
async def test_cookie_auth_is_applied_before_navigation(context):
    """`AuthState.cookies` navigasyondan ÖNCE bağlama yüklenir — sayfa `document.cookie`'yi
    okuduğunda kurbanın çerezini görmeli (gerçek bir DOM XSS'in çalabileceği veriyi simüle eder)."""
    await context.route(f"{ORIGIN}/x", lambda r: _serve(r, COOKIE_ECHO_PAGE))
    driver = BrowserDriver(context=context, timeout_ms=5_000, settle_ms=100)
    auth = AuthState(cookies={"session": "abc123"})
    ev = await driver.navigate_and_observe(f"{ORIGIN}/x", marker="abc123", auth=auth)
    assert ev.executed is True
    assert "session=abc123" in ev.detail


@pytest.mark.asyncio
async def test_scope_denied_raises_before_touching_browser(monkeypatch):
    def _boom():
        raise AssertionError("scope reddettiyse async_playwright hiç çağrılmamalı")

    monkeypatch.setattr("pentestai.browser.driver.async_playwright", _boom)
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    driver = BrowserDriver(policy=PolicyEngine(scope))
    with pytest.raises(ScopeError):
        await driver.navigate_and_observe(f"{ORIGIN}/x", marker="MARKER")


@pytest.mark.asyncio
async def test_budget_exceeded_raises_before_touching_browser(monkeypatch):
    def _boom():
        raise AssertionError("budget aşıldıysa async_playwright hiç çağrılmamalı")

    monkeypatch.setattr("pentestai.browser.driver.async_playwright", _boom)
    driver = BrowserDriver(budget=BudgetTracker(max_total_requests=0))
    with pytest.raises(BudgetExceeded):
        await driver.navigate_and_observe(f"{ORIGIN}/x", marker="MARKER")
