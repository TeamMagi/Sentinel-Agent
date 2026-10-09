"""SmugglingOracle — TIER_C.md C3: CL.TE/TE.CL zamanlama-diferansiyeli kategorizasyonu.

Network'süz (CLAUDE.md §6): `RawHttpClient` DI ile sahte (canned `RawHttpResult` sırası döndüren)
bir çiftle değiştirilir — gerçek soket/zamanlama mekaniği zaten `test_rawsocket_http_client.py`'de
doğrulandı; burada yalnızca `SmugglingOracle`'ın KARAR mantığı (destructive_tests kapısı, eşik,
zaman aşımı) test edilir.
"""
import pytest

from pentestai.models import Scope
from pentestai.net import Replayer
from pentestai.net.replay import ScopeError
from pentestai.oracle import base
from pentestai.oracle.smuggling import SmugglingOracle
from pentestai.policy import PolicyEngine
from pentestai.rawsocket.http_client import RawHttpResult

BASE = "http://target.test.local"


class _FakeRawClient:
    """Sıradaki `RawHttpResult`'ı döner (baseline → CL.TE → TE.CL sırası)."""

    def __init__(self, results):
        self._results = list(results)
        self.calls: list[bytes] = []

    async def send(self, base_url, path, *, raw_request, read_timeout):
        self.calls.append(raw_request)
        return self._results.pop(0)


class _DenyingRawClient:
    async def send(self, base_url, path, *, raw_request, read_timeout):
        raise ScopeError("host out of scope")


def _make_oracle(raw_client, *, destructive_tests: bool = True) -> SmugglingOracle:
    scope = Scope(allowed_hosts=["target.test.local"], allowed_ports=[80],
                  allowed_path_prefixes=["/"], allowed_methods=["GET", "HEAD", "POST"],
                  destructive_tests=destructive_tests)
    replayer = Replayer(PolicyEngine(scope))
    return SmugglingOracle(replayer, BASE, raw_client=raw_client, min_delta_sec=4.0)


@pytest.mark.asyncio
async def test_destructive_tests_disabled_yields_inconclusive_without_any_request():
    raw = _FakeRawClient([])   # send() hiç çağrılmamalı
    oracle = _make_oracle(raw, destructive_tests=False)
    f = await oracle.run(finding_id="F-1")
    assert f.verdict == base.INCONCLUSIVE
    assert raw.calls == []


@pytest.mark.asyncio
async def test_baseline_timeout_yields_inconclusive():
    raw = _FakeRawClient([RawHttpResult(elapsed=6.0, timed_out=True)])
    oracle = _make_oracle(raw)
    f = await oracle.run(finding_id="F-1")
    assert f.verdict == base.INCONCLUSIVE
    assert len(raw.calls) == 1   # taban zaten belirsizse prob GÖNDERİLMEZ


@pytest.mark.asyncio
async def test_baseline_connect_error_yields_inconclusive():
    raw = _FakeRawClient([RawHttpResult(connect_error="connection refused")])
    oracle = _make_oracle(raw)
    f = await oracle.run(finding_id="F-1")
    assert f.verdict == base.INCONCLUSIVE


@pytest.mark.asyncio
async def test_cl_te_confirmed_via_full_timeout():
    raw = _FakeRawClient([
        RawHttpResult(elapsed=0.1),                          # baseline: hızlı
        RawHttpResult(elapsed=6.0, timed_out=True),           # CL.TE: zaman aşımı
    ])
    oracle = _make_oracle(raw)
    f = await oracle.run(finding_id="F-1")
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert f.parameter == "CL.TE"
    assert f.evidence.leaked_markers
    assert len(raw.calls) == 2   # CL.TE zaten kanıtladı — TE.CL GÖNDERİLMEZ


@pytest.mark.asyncio
async def test_te_cl_confirmed_via_delay_delta_without_full_timeout():
    raw = _FakeRawClient([
        RawHttpResult(elapsed=0.1),    # baseline: hızlı
        RawHttpResult(elapsed=0.2),    # CL.TE: hızlı (kanıtlamadı)
        RawHttpResult(elapsed=5.0),    # TE.CL: taban+4.9s ≥ eşik(4.0) — zaman aşımı OLMADAN da CONFIRMED
    ])
    oracle = _make_oracle(raw)
    f = await oracle.run(finding_id="F-1")
    assert f.verdict == base.CONFIRMED
    assert f.parameter == "TE.CL"
    assert len(raw.calls) == 3


@pytest.mark.asyncio
async def test_healthy_target_yields_rejected():
    raw = _FakeRawClient([
        RawHttpResult(elapsed=0.1),
        RawHttpResult(elapsed=0.15),
        RawHttpResult(elapsed=0.12),
    ])
    oracle = _make_oracle(raw)
    f = await oracle.run(finding_id="F-1")
    assert f.verdict == base.REJECTED
    assert not f.evidence.leaked_markers


@pytest.mark.asyncio
async def test_scope_denied_yields_inconclusive():
    oracle = _make_oracle(_DenyingRawClient())
    f = await oracle.run(finding_id="F-1")
    assert f.verdict == base.INCONCLUSIVE
