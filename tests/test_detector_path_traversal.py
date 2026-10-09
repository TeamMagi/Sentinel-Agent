"""Path-traversal / yerel dosya dahil (LFI) dedektörü — CWE-22.

Sahte hedef, dosya parametresindeki traversal'ı ya çözüp sistem dosyası döner ya da süzer.
Kanıt = /etc/passwd imzası (`root:x:0:0:`) yanıtta görünmesi. Network yok: httpx.MockTransport.
0-FP disiplini: imza baseline'da yokken yalnızca saldırı yükünde çıkmalı (negative-control).
"""
import httpx
import pytest

from pentestai.detector.path_traversal import PathTraversalDetector
from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import base
from pentestai.policy import PolicyEngine

ENDPOINT = Endpoint(method="GET", path_template="/download", id_param="file", id_location="query")
BASE = "http://localhost:3000"

_PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"


def _setup(handler, **kw):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    s = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer A"})))
    return store, PathTraversalDetector(Replayer(PolicyEngine(scope)), BASE, **kw), s


async def _run(handler, **kw):
    store, det, s = _setup(handler, **kw)
    fs = await det.run(ENDPOINT, s)
    await store.aclose_all()
    return fs


def _param_value(request) -> str:
    """İlk query parametresinin (dosya adı) decode edilmiş değeri."""
    for _, v in request.url.params.multi_items():
        return v
    return ""


def pt_vuln(request):
    """Zafiyetli: değer dosya sistemi dışına çıkıyorsa gerçek /etc/passwd içeriğini döner."""
    v = _param_value(request).replace("\x00", "")      # null-byte bypass'ı da kabul et
    if "etc/passwd" in v and ".." in v:
        return httpx.Response(200, text=_PASSWD)
    return httpx.Response(200, text="<html>ok</html>")


def pt_safe(request):
    """Güvenli: traversal'ı süzer/sabitler — asla dosya sistemi dışına çıkmaz."""
    return httpx.Response(200, text="<html>ok</html>")


def pt_echo(request):
    """NEAR-MISS: yük değerini HATA MESAJINA yansıtır ama dosyayı OKUMAZ. Naif bir tarayıcı
    'yüküm cevapta göründü' diye flag'ler; biz passwd İMZASINI aradığımız için etmeyiz."""
    v = _param_value(request)
    return httpx.Response(404, text=f"dosya bulunamadı: {v}")


def pt_always_passwd(request):
    """NEAR-MISS: endpoint HER istekte (zararsız baseline dahil) passwd-benzeri içerik döner
    (honeypot / statik örnek sayfa). İmza traversal'a ATFEDİLEMEZ → negative-control başarısız."""
    return httpx.Response(200, text=_PASSWD)


@pytest.mark.asyncio
async def test_lfi_confirmed_when_system_file_leaks():
    fs = await _run(pt_vuln)
    f = fs[0]
    assert f.type == "path_traversal"
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert f.evidence.negative_control and f.evidence.positive_control
    assert f.evidence.leaked_markers


@pytest.mark.asyncio
async def test_lfi_rejected_when_sanitized():
    fs = await _run(pt_safe)
    assert fs[0].verdict == base.REJECTED


@pytest.mark.asyncio
async def test_lfi_no_false_positive_on_payload_echo():
    # Yük değerini gövdeye yansıtan ama dosyayı okumayan sunucu FP üretmemeli (imza yok).
    fs = await _run(pt_echo)
    assert fs[0].verdict != base.CONFIRMED


@pytest.mark.asyncio
async def test_lfi_no_false_positive_when_signature_not_attributable():
    # Baseline'da da passwd imzası varsa (honeypot) sızıntı traversal'a atfedilemez → CONFIRMED değil.
    fs = await _run(pt_always_passwd)
    assert fs[0].verdict != base.CONFIRMED
