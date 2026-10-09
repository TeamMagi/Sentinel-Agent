"""TlsInspector — TIER_C.md C2: ham TLS handshake ile protokol/cipher/sertifika-güven gözlemi.

Network'süz (CLAUDE.md §6): gerçek bir hedefe/internete ASLA gidilmez. Gerçek TLS handshake
mekaniğini test edebilmek için `127.0.0.1`'de kendi (ephemeral portlu) TLS sunucumuzu açarız —
`test_auth_browser.py`'nin gerçek bir tarayıcı SÜRECİ başlatmasıyla aynı ruh (yerel bir motor
sürmek "ağa gitmek" sayılmaz). Self-signed sertifika `openssl` CLI ile ÖNCEDEN üretilir (yeni
Python bağımlılığı — `cryptography` vb. — EKLENMEDEN; `auth/browser.py`'nin TOTP disipliniyle aynı).
"""
import asyncio
import contextlib
import shutil
import ssl
import subprocess

import pytest

from pentestai.models import Scope
from pentestai.net.replay import ScopeError
from pentestai.netscan.tls import TlsInspector, is_weak_cipher
from pentestai.policy import PolicyEngine

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI gerekli (self-signed test sertifikası üretimi)")


def _generate_self_signed_cert(tmp_path) -> tuple[str, str]:
    key = tmp_path / "key.pem"
    cert = tmp_path / "cert.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "2",
         "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"],
        check=True, capture_output=True,
    )
    return str(cert), str(key)


async def _handle_conn(reader, writer):
    with contextlib.suppress(Exception):
        writer.close()
        await writer.wait_closed()


async def _start_tls_server(certfile, keyfile):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    server = await asyncio.start_server(_handle_conn, "127.0.0.1", 0, ssl=ctx)
    port = server.sockets[0].getsockname()[1]
    return server, port


def _scope(port: int) -> Scope:
    return Scope(allowed_hosts=["127.0.0.1"], allowed_ports=[port], allowed_path_prefixes=["/"])


@pytest.mark.asyncio
async def test_self_signed_untrusted_cert_is_detected(tmp_path):
    cert, key = _generate_self_signed_cert(tmp_path)
    server, port = await _start_tls_server(cert, key)
    try:
        inspector = TlsInspector(policy=PolicyEngine(_scope(port)), timeout=3.0)
        ev = await inspector.inspect("127.0.0.1", port)
        assert ev.reachable is True
        assert ev.verified_ok is False
        assert ev.cert_issue == "self_signed"
        assert ev.protocol is not None   # raw handshake da başarılı — protokol/cipher gözlendi
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_cert_trusted_via_ssl_cert_file_yields_verified_ok(tmp_path, monkeypatch):
    """Aynı self-signed sertifika, istemcinin güven mağazasına (SSL_CERT_FILE) KENDİ CA'sı olarak
    eklenirse `verified_ok=True` olmalı — OpenSSL'in verify kararı KODUN elle yorumu değil,
    doğrudan güven mağazasına bağlı deterministik bir sonuçtur."""
    cert, key = _generate_self_signed_cert(tmp_path)
    server, port = await _start_tls_server(cert, key)
    try:
        monkeypatch.setenv("SSL_CERT_FILE", cert)
        inspector = TlsInspector(policy=PolicyEngine(_scope(port)), timeout=3.0)
        ev = await inspector.inspect("127.0.0.1", port)
        assert ev.reachable is True
        assert ev.verified_ok is True
        assert ev.cert_issue is None
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_unreachable_port_is_not_reachable():
    # Hiçbir şeyin dinlemediği bir port — TLS'siz/kapalı port misconfig KANITI değildir.
    inspector = TlsInspector(policy=PolicyEngine(_scope(1)), timeout=1.0)
    ev = await inspector.inspect("127.0.0.1", 1)
    assert ev.reachable is False
    assert ev.verified_ok is None
    assert ev.protocol is None


@pytest.mark.asyncio
async def test_scope_denied_raises_before_touching_socket(monkeypatch):
    def _boom(*a, **kw):
        raise AssertionError("scope reddettiyse open_connection hiç çağrılmamalı")

    monkeypatch.setattr("asyncio.open_connection", _boom)
    scope = Scope(allowed_hosts=["other.test.local"], allowed_ports=[443], allowed_path_prefixes=["/"])
    inspector = TlsInspector(policy=PolicyEngine(scope))
    with pytest.raises(ScopeError):
        await inspector.inspect("127.0.0.1", 443)


def test_is_weak_cipher():
    assert is_weak_cipher("ECDHE-RSA-AES256-GCM-SHA384") is False
    assert is_weak_cipher("TLS_AES_256_GCM_SHA384") is False
    assert is_weak_cipher("DES-CBC3-SHA") is True
    assert is_weak_cipher("EXP-RC4-MD5") is True
    assert is_weak_cipher(None) is False
    assert is_weak_cipher("") is False
