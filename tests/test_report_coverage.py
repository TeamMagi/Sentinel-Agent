"""CoverageReporter — R-D1 (GOREVLER.md, ROADMAP.md Eksen D): per-rol kapsam tablosu.

"Hangi aktör hangi endpoint'e ulaştı" tablosu, Finding.evidence'ından (baseline/attack
response status'leri) + Finding.victim_as/found_as'tan türetilir — ayrı izleme yok.
"""
import httpx
import pytest

from pentestai.models import Actor, CapturedRequest, Evidence, Finding, NormalizedResponse
from pentestai.net.session_store import SessionStore
from pentestai.report import HtmlReporter, MarkdownReporter
from pentestai.report.coverage import CoverageReporter


def _resp(status: int) -> NormalizedResponse:
    return NormalizedResponse(status=status)


def _finding(method, endpoint, *, victim_as, found_as, baseline_status=None, attack_status=None) -> Finding:
    ev = Evidence()
    if baseline_status is not None:
        ev.baseline_request = CapturedRequest(method=method, url="http://x" + endpoint)
        ev.baseline_response = _resp(baseline_status)
    if attack_status is not None:
        ev.attack_request = CapturedRequest(method=method, url="http://x" + endpoint)
        ev.attack_response = _resp(attack_status)
    return Finding(id="F-001", type="idor", endpoint=endpoint, method=method, verdict="REJECTED",
                   victim_as=victim_as, found_as=found_as, evidence=ev)


def _store():
    return SessionStore(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})))


@pytest.mark.asyncio
async def test_reached_true_on_2xx_response():
    store = _store()
    A = store.create(Actor(name="user_A", role="user"))
    B = store.create(Actor(name="user_B", role="admin"))
    findings = [_finding("GET", "/api/orders/{id}", victim_as="user_A", found_as="user_B",
                          baseline_status=200, attack_status=403)]
    rows = CoverageReporter().build(findings, [A, B])
    by_actor = {(r.actor, r.method, r.endpoint): r for r in rows}
    assert by_actor[("user_A", "GET", "/api/orders/{id}")].reached is True
    assert by_actor[("user_A", "GET", "/api/orders/{id}")].role == "user"
    assert by_actor[("user_B", "GET", "/api/orders/{id}")].reached is False
    assert by_actor[("user_B", "GET", "/api/orders/{id}")].role == "admin"
    await store.aclose_all()


@pytest.mark.asyncio
async def test_reached_upgrades_to_true_if_any_call_succeeds():
    # Aynı (actor, method, endpoint) için birden çok Finding olabilir (farklı kurbanlarla) —
    # bir tanesi bile 2xx gördüyse reached=True kalmalı (asla geriye False'a düşmemeli).
    store = _store()
    A = store.create(Actor(name="user_A", role="user"))
    B = store.create(Actor(name="user_B", role="user"))
    findings = [
        _finding("GET", "/api/orders/{id}", victim_as="user_A", found_as="user_B",
                  baseline_status=200, attack_status=403),
        _finding("GET", "/api/orders/{id}", victim_as="user_A", found_as="user_B",
                  baseline_status=200, attack_status=200),
    ]
    rows = CoverageReporter().build(findings, [A, B])
    row = next(r for r in rows if r.actor == "user_B")
    assert row.reached is True
    await store.aclose_all()


@pytest.mark.asyncio
async def test_missing_actor_or_response_ignored():
    store = _store()
    A = store.create(Actor(name="user_A", role="user"))
    findings = [_finding("GET", "/x", victim_as=None, found_as=None)]   # ne response ne aktör
    rows = CoverageReporter().build(findings, [A])
    assert rows == []
    await store.aclose_all()


@pytest.mark.asyncio
async def test_markdown_report_includes_coverage_table_and_found_as():
    store = _store()
    A = store.create(Actor(name="user_A", role="user"))
    B = store.create(Actor(name="user_B", role="user"))
    findings = [_finding("GET", "/api/orders/{id}", victim_as="user_A", found_as="user_B",
                          baseline_status=200, attack_status=200)]
    md = MarkdownReporter().render(findings, target="http://x", sessions=[A, B])
    assert "## Per-Role Coverage" in md
    assert "user_A" in md and "user_B" in md
    assert "found as `user_B`" in md
    await store.aclose_all()


@pytest.mark.asyncio
async def test_markdown_report_without_sessions_is_backward_compatible():
    findings = [_finding("GET", "/x", victim_as="user_A", found_as="user_B", attack_status=200)]
    md = MarkdownReporter().render(findings, target="http://x")
    assert "Per-Role Coverage" not in md


@pytest.mark.asyncio
async def test_html_report_embeds_coverage_payload():
    store = _store()
    A = store.create(Actor(name="user_A", role="user"))
    B = store.create(Actor(name="user_B", role="user"))
    findings = [_finding("GET", "/api/orders/{id}", victim_as="user_A", found_as="user_B",
                          baseline_status=200, attack_status=200)]
    html = HtmlReporter().render(findings, target="http://x", sessions=[A, B])
    assert '"coverage":' in html
    assert "user_B" in html
    await store.aclose_all()
