"""InfoLeakDetector — hata tetikleme + response/header imza analizi. A5 (Tier A)."""
import httpx
import pytest

from pentestai.detector.info_leak import InfoLeakDetector
from pentestai.models import Actor, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"


def fingerprint_handler(request):
    return httpx.Response(200, text="<html>hello</html>",
                          headers={"X-Powered-By": "Express", "Server": "nginx/1.18.0"})


def clean_handler(request):
    return httpx.Response(200, text="<html>hello</html>", headers={"Server": "cloudflare"})


def stack_trace_handler(request):
    return httpx.Response(500, text=(
        'Traceback (most recent call last):\n  File "app.py", line 42, in handler\n'
        "ZeroDivisionError: division by zero"))


def error_trigger_handler(request):
    oid = request.url.path.rsplit("/", 1)[-1]
    if oid == "9" * 40:   # yalnızca aşırı-uzun malformed id hata tetikler
        return httpx.Response(500, text=(
            'Traceback (most recent call last):\n  File "app.py", line 10, in get_order\n'
            "OverflowError: int too large"))
    return httpx.Response(200, json={"id": oid})


def _setup(handler):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(transport=httpx.MockTransport(handler))
    session = store.create(Actor(name="user_A", role="user"))
    detector = InfoLeakDetector(Replayer(PolicyEngine(scope)), BASE)
    return store, detector, session


@pytest.mark.asyncio
async def test_fingerprint_header_detected():
    store, detector, session = _setup(fingerprint_handler)
    findings = await detector.scan(session)
    assert any(f.type == "info_leak" for f in findings)
    assert findings   # X-Powered-By + versionlu Server header → en az bir bulgu
    await store.aclose_all()


@pytest.mark.asyncio
async def test_clean_headers_no_findings():
    store, detector, session = _setup(clean_handler)
    findings = await detector.scan(session)
    assert findings == []
    await store.aclose_all()


@pytest.mark.asyncio
async def test_stack_trace_in_body_detected():
    store, detector, session = _setup(stack_trace_handler)
    findings = await detector.scan(session)
    assert any("stack trace" in f.evidence.leaked_markers[0].lower() for f in findings)
    # ham stack trace metni evidence'a yazılmaz
    assert all("ZeroDivisionError" not in m for f in findings for m in f.evidence.leaked_markers)
    await store.aclose_all()


@pytest.mark.asyncio
async def test_debug_mode_detected():
    def werkzeug_debug_handler(request):
        return httpx.Response(500, text="<title>Werkzeug Debugger</title><h1>Traceback</h1>")

    store, detector, session = _setup(werkzeug_debug_handler)
    findings = await detector.scan(session)
    assert any("debug mode" in f.evidence.leaked_markers[0].lower() for f in findings)
    await store.aclose_all()


@pytest.mark.asyncio
async def test_error_trigger_finds_stack_trace_on_malformed_id():
    store, detector, session = _setup(error_trigger_handler)
    ep = Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id")
    findings = await detector.scan_error_triggers(session, [ep])
    assert len(findings) == 1
    assert findings[0].verdict == "CONFIRMED" and findings[0].type == "info_leak"
    assert "OverflowError" not in findings[0].evidence.leaked_markers[0]
    await store.aclose_all()


@pytest.mark.asyncio
async def test_error_trigger_no_findings_when_clean():
    def clean_orders(request):
        return httpx.Response(200, json={"id": request.url.path.rsplit("/", 1)[-1]})

    store, detector, session = _setup(clean_orders)
    ep = Endpoint(method="GET", path_template="/api/orders/{id}", id_param="id")
    findings = await detector.scan_error_triggers(session, [ep])
    assert findings == []
    await store.aclose_all()
