"""JWT algoritma karışıklığı + kid enjeksiyonu dedektörü.

Sahte korumalı endpoint; kanıt = forge token'ın gerçek token'la aynı 200 yanıtını alması.
Network yok: httpx.MockTransport. alg-confusion testi gerçek RSA anahtarı üretir.
"""
import base64
import hashlib
import hmac
import json

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from pentestai.detector.jwt_confusion import JwtConfusionDetector
from pentestai.models import Actor, AuthState, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import base
from pentestai.policy import PolicyEngine

ENDPOINT = Endpoint(method="GET", path_template="/rest/data", id_location="query")
BASE = "http://localhost:3000"
OK_BODY = {"user": "admin", "balance": 100}


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


# Gerçek (baseline) token — sunucu eşitlikle kabul eder (RS256 doğrulamasını taklit).
REAL = f"{_b64e(json.dumps({'alg': 'RS256'}).encode())}.{_b64e(json.dumps({'sub': 'admin'}).encode())}.realsig"


def _hs256(signing_input: str, secret: bytes) -> str:
    return _b64e(hmac.new(secret, signing_input.encode(), hashlib.sha256).digest())


def _header(tok: str) -> dict:
    h = tok.split(".")[0]
    return json.loads(base64.urlsafe_b64decode(h + "=="))


def _setup(handler):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(handler))
    s = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": f"Bearer {REAL}"})))
    return store, JwtConfusionDetector(Replayer(PolicyEngine(scope)), BASE), s


async def _run(handler):
    store, det, s = _setup(handler)
    fs = await det.run(ENDPOINT, s)
    await store.aclose_all()
    return fs


def _bearer(request) -> str:
    return request.headers.get("authorization", "").split(" ", 1)[-1]


# --- kid enjeksiyonu ---

def kid_vuln(request):
    """kid'i dosya yolu sanıp /dev/null'ı (boş) anahtar olarak kullanan savunmasız sunucu."""
    tok = _bearer(request)
    if tok == REAL:
        return httpx.Response(200, json=OK_BODY)
    h, p, s = tok.split(".")
    kid = _header(tok).get("kid", "")
    # boş-anahtar kaynağı + boş-secret HS256 doğrularsa kabul (savunmasız davranış).
    if kid in ("/dev/null", "", "../../../../../../../../../../dev/null") and s == _hs256(f"{h}.{p}", b""):
        return httpx.Response(200, json=OK_BODY)
    return httpx.Response(401, text="invalid token")


def jwt_secure(request):
    """Yalnızca gerçek token'ı kabul eden güvenli sunucu."""
    return httpx.Response(200, json=OK_BODY) if _bearer(request) == REAL \
        else httpx.Response(401, text="invalid token")


@pytest.mark.asyncio
async def test_kid_injection_confirmed():
    fs = await _run(kid_vuln)
    kid = next(f for f in fs if f.parameter == "kid")
    assert kid.verdict == base.CONFIRMED and kid.confidence == "high"
    assert kid.evidence.leaked_markers


@pytest.mark.asyncio
async def test_kid_injection_rejected_on_secure_server():
    fs = await _run(jwt_secure)
    kid = next(f for f in fs if f.parameter == "kid")
    assert kid.verdict == base.REJECTED


# --- RS256 → HS256 algoritma karışıklığı ---

_PRIV = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PUB = _PRIV.public_key()
_PUB_PEM = _PUB.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()
_JWK = json.loads(RSAAlgorithm.to_jwk(_PUB))


def alg_confusion_vuln(request):
    """JWKS'i açık eden ve public key'i HMAC secret'ı olarak kabul eden savunmasız sunucu."""
    if request.url.path == "/.well-known/jwks.json":
        return httpx.Response(200, json={"keys": [_JWK]})
    tok = _bearer(request)
    if tok == REAL:
        return httpx.Response(200, json=OK_BODY)
    h, p, s = tok.split(".")
    if _header(tok).get("alg") == "HS256" and s == _hs256(f"{h}.{p}", _PUB_PEM.encode()):
        return httpx.Response(200, json=OK_BODY)
    return httpx.Response(401, text="invalid token")


@pytest.mark.asyncio
async def test_alg_confusion_confirmed():
    fs = await _run(alg_confusion_vuln)
    alg = next(f for f in fs if f.parameter == "alg-confusion")
    assert alg.verdict == base.CONFIRMED and alg.confidence == "high"
    assert alg.evidence.leaked_markers


@pytest.mark.asyncio
async def test_alg_confusion_skipped_without_jwks():
    # JWKS yoksa alg-confusion bulgusu hiç üretilmez (gürültü yok); yalnızca kid bulgusu döner.
    fs = await _run(jwt_secure)
    assert not any(f.parameter == "alg-confusion" for f in fs)


@pytest.mark.asyncio
async def test_no_finding_without_jwt_session():
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(base_url=BASE, transport=httpx.MockTransport(jwt_secure))
    s = store.create(Actor(name="x", auth=AuthState(headers={})))   # JWT yok
    det = JwtConfusionDetector(Replayer(PolicyEngine(scope)), BASE)
    fs = await det.run(ENDPOINT, s)
    await store.aclose_all()
    assert fs == []
