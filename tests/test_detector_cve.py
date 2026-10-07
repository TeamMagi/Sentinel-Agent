"""VersionCveDetector — sürüm fingerprint → yerel CVE tablosu eşleme. B7."""
import httpx
import pytest

from pentestai.detector.cve import CveDatabase, CveEntry, VersionCveDetector
from pentestai.models import Actor, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"


def _setup(server_header: str):
    def handler(request):
        return httpx.Response(200, text="hello", headers={"Server": server_header})

    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(transport=httpx.MockTransport(handler))
    session = store.create(Actor(name="user_A"))
    detector = VersionCveDetector(Replayer(PolicyEngine(scope)), BASE)
    return store, detector, session


@pytest.mark.asyncio
async def test_vulnerable_old_nginx_confirmed():
    store, detector, session = _setup("nginx/1.18.0")
    findings = await detector.scan(session)
    assert len(findings) == 1
    assert findings[0].verdict == "CONFIRMED" and findings[0].type == "vulnerable_component"
    assert "CVE-2021-23017" in findings[0].evidence.leaked_markers[0]
    await store.aclose_all()


@pytest.mark.asyncio
async def test_patched_nginx_no_finding():
    store, detector, session = _setup("nginx/1.25.3")
    findings = await detector.scan(session)
    assert findings == []
    await store.aclose_all()


@pytest.mark.asyncio
async def test_unknown_product_no_finding():
    store, detector, session = _setup("MyCustomServer/9.9.9")
    findings = await detector.scan(session)
    assert findings == []
    await store.aclose_all()


def test_cve_database_lookup_and_extension():
    db = CveDatabase(extra=(CveEntry("widget", "2.0.0", "CVE-9999-0001", "Low", "test"),))
    assert db.lookup("nginx", "1.18.0")
    assert not db.lookup("nginx", "1.25.3")
    assert db.lookup("widget", "1.0.0")
