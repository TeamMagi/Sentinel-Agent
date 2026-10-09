"""TlsDetector — TIER_C.md C2: `TlsEvidence` → `Finding` kategorileştirme.

Network'süz (CLAUDE.md §6): `TlsInspector` DI ile sahte (canned `TlsEvidence` döndüren) bir
çiftle değiştirilir — gerçek soket/handshake mekaniği zaten `test_tls_inspector.py`'de
doğrulandı; burada yalnızca `TlsDetector`'ın KATEGORİZASYON mantığı test edilir.
"""
import pytest

from pentestai.detector.tls import TlsDetector
from pentestai.models import Actor, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.net.replay import ScopeError
from pentestai.netscan.tls import TlsEvidence
from pentestai.oracle import base
from pentestai.policy import PolicyEngine


class _FakeInspector:
    def __init__(self, evidence: TlsEvidence):
        self._evidence = evidence
        self.calls: list[tuple[str, int]] = []

    async def inspect(self, host: str, port: int) -> TlsEvidence:
        self.calls.append((host, port))
        return self._evidence


class _DenyingInspector:
    async def inspect(self, host: str, port: int) -> TlsEvidence:
        raise ScopeError("host out of scope")


def _setup(inspector):
    scope = Scope(allowed_hosts=["target.test.local"], allowed_ports=[443], allowed_path_prefixes=["/"])
    replayer = Replayer(PolicyEngine(scope))
    detector = TlsDetector(replayer, "https://target.test.local", tls_inspector=inspector)
    store = SessionStore()
    A = Actor(name="user_A")
    return detector, store, store.create(A)


@pytest.mark.asyncio
async def test_certificate_issue_yields_confirmed_finding():
    ev = TlsEvidence(reachable=True, verified_ok=False, cert_issue="expired",
                     verify_message="certificate has expired", protocol="TLSv1.3",
                     cipher_name="TLS_AES_256_GCM_SHA384")
    detector, store, s = _setup(_FakeInspector(ev))
    findings = await detector.scan(s)
    assert len(findings) == 1
    f = findings[0]
    assert f.type == "certificate_misconfiguration" and f.verdict == base.CONFIRMED
    assert "sertifikanın süresi dolmuş" in f.evidence.leaked_markers[0]
    await store.aclose_all()


@pytest.mark.asyncio
async def test_weak_protocol_yields_confirmed_finding():
    ev = TlsEvidence(reachable=True, verified_ok=True, protocol="TLSv1.1",
                     cipher_name="ECDHE-RSA-AES256-GCM-SHA384")
    detector, store, s = _setup(_FakeInspector(ev))
    findings = await detector.scan(s)
    assert len(findings) == 1
    assert findings[0].type == "tls_misconfiguration" and findings[0].parameter == "protocol_version"
    await store.aclose_all()


@pytest.mark.asyncio
async def test_weak_cipher_yields_confirmed_finding():
    ev = TlsEvidence(reachable=True, verified_ok=True, protocol="TLSv1.2", cipher_name="DES-CBC3-SHA")
    detector, store, s = _setup(_FakeInspector(ev))
    findings = await detector.scan(s)
    assert len(findings) == 1
    assert findings[0].type == "tls_misconfiguration" and findings[0].parameter == "cipher_suite"
    await store.aclose_all()


@pytest.mark.asyncio
async def test_healthy_tls_yields_no_findings():
    ev = TlsEvidence(reachable=True, verified_ok=True, protocol="TLSv1.3",
                     cipher_name="TLS_AES_256_GCM_SHA384")
    detector, store, s = _setup(_FakeInspector(ev))
    findings = await detector.scan(s)
    assert findings == []
    await store.aclose_all()


@pytest.mark.asyncio
async def test_unreachable_target_yields_no_findings():
    detector, store, s = _setup(_FakeInspector(TlsEvidence(reachable=False)))
    findings = await detector.scan(s)
    assert findings == []
    await store.aclose_all()


@pytest.mark.asyncio
async def test_scope_denied_returns_empty():
    detector, store, s = _setup(_DenyingInspector())
    findings = await detector.scan(s)
    assert findings == []
    await store.aclose_all()


@pytest.mark.asyncio
async def test_multiple_issues_yield_multiple_findings():
    ev = TlsEvidence(reachable=True, verified_ok=False, cert_issue="self_signed",
                     verify_message="self signed certificate", protocol="TLSv1.1",
                     cipher_name="RC4-MD5")
    detector, store, s = _setup(_FakeInspector(ev))
    findings = await detector.scan(s)
    types = {f.type for f in findings}
    assert types == {"certificate_misconfiguration", "tls_misconfiguration"}
    assert len(findings) == 3
    await store.aclose_all()
