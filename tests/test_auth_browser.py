"""BrowserAuthProvider — Playwright tabanlı interaktif login + TOTP MFA.

Network'süz (CLAUDE.md §6): gerçek bir hedefe gidilmez. Sahte bir origin
(`https://auth.test.local`) `BrowserContext.route()` ile TAMAMEN yerelden (route interception
gerçek DNS/soket açmadan yanıtı üretir) sunulur — `httpx.MockTransport`'un Playwright karşılığı.
`context` DI ile enjekte edilir (bkz. BrowserAuthProvider docstring'i) — provider kendi
tarayıcısını açmaz, testler tek bir paylaşılan tarayıcıyı (session-scope fixture) kullanır.
"""
import base64

import pytest
import pytest_asyncio
from playwright.async_api import async_playwright

from pentestai.auth.browser import BrowserAuthProvider
from pentestai.models import Scope
from pentestai.net.replay import ScopeError
from pentestai.policy import PolicyEngine

ORIGIN = "https://auth.test.local"

SIMPLE_LOGIN_PAGE = """
<html><body>
  <input name="email" />
  <input type="password" name="password" />
  <button type="submit">Giriş</button>
  <script>
    document.querySelector('button').addEventListener('click', function (e) {
      e.preventDefault();
      localStorage.setItem('token', 'tok-e2e-12345');
      document.cookie = 'session=abc123; path=/';
    });
  </script>
</body></html>
"""

MFA_LOGIN_PAGE = """
<html><body>
  <div id="step1">
    <input name="email" />
    <input type="password" name="password" />
    <button type="submit" id="go1">Giriş</button>
  </div>
  <div id="step2" style="display:none">
    <input id="otp" />
    <button type="submit" id="go2">Onayla</button>
  </div>
  <div id="dashboard" style="display:none">welcome</div>
  <script>
    document.getElementById('go1').addEventListener('click', function (e) {
      e.preventDefault();
      document.getElementById('step1').style.display = 'none';
      document.getElementById('step2').style.display = 'block';
    });
    document.getElementById('go2').addEventListener('click', function (e) {
      e.preventDefault();
      var otp = document.getElementById('otp').value;
      if (/^\\d{6}$/.test(otp)) {
        localStorage.setItem('token', 'tok-mfa-99999');
        document.getElementById('dashboard').style.display = 'block';
      }
    });
  </script>
</body></html>
"""


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
async def test_simple_login_extracts_cookie_and_bearer_token(context):
    await context.route(f"{ORIGIN}/login", lambda r: _serve(r, SIMPLE_LOGIN_PAGE))
    provider = BrowserAuthProvider(
        f"{ORIGIN}/login", {"email": "a@test.local", "password": "x"}, context=context,
    )
    state = await provider.acquire()
    assert state.cookies == {"session": "abc123"}
    assert state.headers == {"Authorization": "Bearer tok-e2e-12345"}


@pytest.mark.asyncio
async def test_mfa_totp_flow_reaches_dashboard_and_extracts_token(context):
    await context.route(f"{ORIGIN}/login", lambda r: _serve(r, MFA_LOGIN_PAGE))
    secret = base64.b32encode(b"12345678901234567890").decode()
    provider = BrowserAuthProvider(
        f"{ORIGIN}/login", {"email": "a@test.local", "password": "x"},
        submit_selector="#go1", mfa_code_selector="#otp", mfa_submit_selector="#go2",
        mfa_totp_secret=secret, success_selector="#dashboard", context=context,
    )
    state = await provider.acquire()
    assert state.headers == {"Authorization": "Bearer tok-mfa-99999"}


@pytest.mark.asyncio
async def test_mfa_required_without_totp_secret_raises(context):
    await context.route(f"{ORIGIN}/login", lambda r: _serve(r, MFA_LOGIN_PAGE))
    provider = BrowserAuthProvider(
        f"{ORIGIN}/login", {"email": "a@test.local", "password": "x"},
        submit_selector="#go1", mfa_code_selector="#otp", mfa_submit_selector="#go2",
        mfa_totp_secret=None, context=context,
    )
    with pytest.raises(RuntimeError, match="mfa_totp_secret"):
        await provider.acquire()


@pytest.mark.asyncio
async def test_scope_denied_login_url_raises_before_touching_browser(monkeypatch):
    def _boom():
        raise AssertionError("scope reddettiyse async_playwright hiç çağrılmamalı")

    monkeypatch.setattr("pentestai.auth.browser.async_playwright", _boom)
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    provider = BrowserAuthProvider(
        f"{ORIGIN}/login", {"email": "a@test.local", "password": "x"},
        policy=PolicyEngine(scope),
    )
    with pytest.raises(ScopeError):
        await provider.acquire()


def test_totp_matches_rfc6238_appendix_b_vector(monkeypatch):
    # https://www.rfc-editor.org/rfc/rfc6238 Ek B: sır="12345678901234567890" (ASCII),
    # SHA1, T=59s → 8 haneli OTP "94287082".
    secret = base64.b32encode(b"12345678901234567890").decode()
    monkeypatch.setattr("pentestai.auth.browser.time.time", lambda: 59)
    assert BrowserAuthProvider._totp_now(secret, digits=8) == "94287082"
