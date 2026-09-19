"""FileUploadOracle — dosya uzantısı/MIME tipi bypass testi. B1."""
import re

import httpx
import pytest

from pentestai.models import Actor, Endpoint, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.oracle import base
from pentestai.oracle.file_upload import FileUploadOracle
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"
EP = Endpoint(method="POST", path_template="/api/uploads", id_param="id")


def _parse_multipart(request):
    ctype = request.headers.get("content-type", "")
    boundary = ctype.split("boundary=")[-1].encode()
    for part in request.content.split(b"--" + boundary):
        if b"Content-Disposition" in part:
            header, _, body = part.partition(b"\r\n\r\n")
            m = re.search(rb'filename="([^"]*)"', header)
            ctm = re.search(rb"Content-Type: (\S+)", header)
            if m:
                return m.group(1).decode(), (ctm.group(1).decode() if ctm else ""), body.rstrip(b"\r\n")
    return None, None, b""


def make_app(*, filter_mode: str):
    """filter_mode: 'none' (validasyon yok) | 'content_type' (yalnızca Content-Type kontrolü,
    bypass'a açık) | 'robust' (dosya adında '.php' varsa reddeder — tüm varyantları yakalar)."""
    store: dict[str, bytes] = {}

    def handler(request):
        if request.method == "POST" and request.url.path == "/api/uploads":
            filename, content_type, content = _parse_multipart(request)
            if filter_mode == "content_type" and content_type == "application/x-php":
                return httpx.Response(400, json={"error": "içerik tipi izinli değil"})
            if filter_mode == "robust" and ".php" in filename.lower():
                return httpx.Response(400, json={"error": "uzantı izinli değil"})
            store[filename] = content
            return httpx.Response(201, json={"path": f"/api/uploads/{filename}"})
        if request.method == "GET" and request.url.path.startswith("/api/uploads/"):
            fn = request.url.path.rsplit("/", 1)[-1]
            if fn in store:
                return httpx.Response(200, text=store[fn].decode(errors="replace"))
            return httpx.Response(404, json={})
        return httpx.Response(404, json={})

    return handler


def _setup(handler):
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"],
                  allowed_methods=["GET", "POST"], destructive_tests=True)
    store = SessionStore(transport=httpx.MockTransport(handler))
    A = Actor(name="user_A")
    oracle = FileUploadOracle(Replayer(PolicyEngine(scope)), BASE)
    return store, oracle, store.create(A)


@pytest.mark.asyncio
async def test_confirmed_when_no_validation_at_all():
    store, oracle, A = _setup(make_app(filter_mode="none"))
    f = await oracle.run(EP, A, A)
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert f.evidence.positive_control and not f.evidence.negative_control
    assert "doğrulaması YOK" in f.evidence.leaked_markers[0]
    await store.aclose_all()


@pytest.mark.asyncio
async def test_confirmed_via_mime_spoof_bypass():
    store, oracle, A = _setup(make_app(filter_mode="content_type"))
    f = await oracle.run(EP, A, A)
    assert f.verdict == base.CONFIRMED and f.confidence == "high"
    assert f.evidence.negative_control is True    # çıplak php reddedildi
    assert "bypass" in f.evidence.leaked_markers[0].lower()
    await store.aclose_all()


@pytest.mark.asyncio
async def test_rejected_when_filter_is_robust():
    store, oracle, A = _setup(make_app(filter_mode="robust"))
    f = await oracle.run(EP, A, A)
    assert f.verdict == base.REJECTED
    await store.aclose_all()


@pytest.mark.asyncio
async def test_inconclusive_when_upload_pipeline_broken():
    def broken_handler(request):
        return httpx.Response(500, json={"error": "boom"})

    store, oracle, A = _setup(broken_handler)
    f = await oracle.run(EP, A, A)
    assert f.verdict == base.INCONCLUSIVE
    await store.aclose_all()
