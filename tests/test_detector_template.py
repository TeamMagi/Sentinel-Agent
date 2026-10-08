"""Nuclei-tarzı YAML template dedektörü (RK-12). Network yok (MockTransport).

Kabul: en az bir dedektör template'ten sürülüyor; kötü template güvenle eleniyor (tarama çökmez);
ağsız çalışır."""
import pathlib

import httpx
import pytest

from pentestai.detector import TemplateDetector, load_templates
from pentestai.detector.template import Matcher, Template, TemplateInfo
from pentestai.models import NormalizedResponse, Scope
from pentestai.net import Replayer, SessionStore
from pentestai.policy import PolicyEngine

BASE = "http://localhost:3000"
REPO_TEMPLATES = pathlib.Path(__file__).resolve().parents[1] / "templates"


# ---------------- Matcher / Template birim ----------------

def _resp(status=200, body="", headers=None):
    return NormalizedResponse(status=status, headers=headers or {}, body_text=body,
                              body_normalized=body)


def test_status_and_word_matchers():
    t = Template(id="t", info=TemplateInfo(name="x"), type="exposure", path="/a",
                 matchers=[Matcher(type="status", status=[200]),
                           Matcher(type="word", part="body", words=['"activeProfiles"'])])
    assert t.evaluate(_resp(200, '{"activeProfiles":["prod"]}')) is True
    assert t.evaluate(_resp(404, '{"activeProfiles":[]}')) is False   # status matcher düşer (AND)


def test_header_absent_matcher():
    m = Matcher(type="header_absent", condition="and",
                headers=["Strict-Transport-Security", "Content-Security-Policy"])
    assert m.evaluate(_resp(200, "", {})) is True                          # ikisi de yok
    assert m.evaluate(_resp(200, "", {"strict-transport-security": "max-age=1"})) is False


def test_negative_and_regex_matchers():
    m = Matcher(type="regex", part="body", regex=[r"SQLITE_ERROR"], negative=True)
    assert m.evaluate(_resp(200, "ok")) is True                # yok → negative eşleşir
    assert m.evaluate(_resp(200, "SQLITE_ERROR")) is False


def test_or_condition_between_matchers():
    t = Template(id="t", info=TemplateInfo(name="x"), path="/a", matchers_condition="or",
                 matchers=[Matcher(type="status", status=[500]),
                           Matcher(type="word", words=["boom"])])
    assert t.evaluate(_resp(200, "boom")) is True    # biri yeter (or)


# ---------------- Güvenli yükleme (kötü template elenir) ----------------

def test_load_templates_skips_invalid_keeps_valid(tmp_path):
    (tmp_path / "good.yaml").write_text(
        "id: good\ninfo:\n  name: iyi\ntype: exposure\npath: /a\n"
        "matchers:\n  - type: status\n    status: [200]\n", encoding="utf-8")
    (tmp_path / "bad_yaml.yaml").write_text("id: x\ninfo: [not-a-dict\n", encoding="utf-8")
    (tmp_path / "bad_schema.yaml").write_text("id: y\ninfo:\n  name: z\n", encoding="utf-8")  # matchers yok
    (tmp_path / "bad_regex.yaml").write_text(
        "id: z\ninfo:\n  name: z\npath: /a\nmatchers:\n  - type: regex\n    regex: ['(']\n",
        encoding="utf-8")
    templates, errors = load_templates(tmp_path)
    assert [t.id for t in templates] == ["good"]
    assert len(errors) == 3   # bad_yaml + bad_schema + bad_regex


def test_load_templates_missing_dir_returns_error():
    templates, errors = load_templates("/gerçekten/olmayan/dizin")
    assert templates == [] and errors and "yok" in errors[0]


def test_repo_templates_load_without_errors():
    templates, errors = load_templates(REPO_TEMPLATES)
    assert errors == [], f"depo template'leri hatalı: {errors}"
    assert len(templates) >= 1   # en az bir dedektör template'ten sürülüyor


# ---------------- Ağsız tarama (MockTransport) ----------------

def _handler(request):
    path = request.url.path
    if path == "/actuator/env":
        return httpx.Response(200, json={"activeProfiles": ["prod"], "propertySources": []})
    if path == "/":
        return httpx.Response(200, text="<html>app</html>")   # güvenlik header'ları YOK
    return httpx.Response(404, text="not found")               # bogus path


async def _detector(templates):
    from pentestai.models import Actor, AuthState
    scope = Scope(allowed_hosts=["localhost"], allowed_ports=[3000], allowed_path_prefixes=["/"])
    store = SessionStore(transport=httpx.MockTransport(_handler))
    session = store.create(Actor(name="user_A", auth=AuthState(headers={"Authorization": "Bearer A"})))
    det = TemplateDetector(Replayer(PolicyEngine(scope)), BASE, templates)
    return store, det, session


@pytest.mark.asyncio
async def test_scan_confirms_content_signature_template():
    tpl = Template(id="actuator", info=TemplateInfo(name="actuator ifşası", severity="high"),
                   type="exposure", path="/actuator/env",
                   matchers=[Matcher(type="status", status=[200]),
                             Matcher(type="word", words=['"activeProfiles"'])])
    store, det, session = await _detector([tpl])
    findings = await det.scan(session)
    await store.aclose_all()
    assert len(findings) == 1
    f = findings[0]
    assert f.verdict == "CONFIRMED" and f.type == "exposure" and f.endpoint == "/actuator/env"
    assert f.severity_suggested == "high"       # ipucu korunur
    assert "activeProfiles" not in " ".join(f.evidence.leaked_markers)   # ham içerik yok (§5)


@pytest.mark.asyncio
async def test_scan_header_absent_template_no_fp_guard():
    tpl = Template(id="hdr", info=TemplateInfo(name="eksik header"), type="security_headers",
                   path="/", fp_guard=False,
                   matchers=[Matcher(type="status", status=[200]),
                             Matcher(type="header_absent", condition="and",
                                     headers=["Strict-Transport-Security", "Content-Security-Policy"])])
    store, det, session = await _detector([tpl])
    findings = await det.scan(session)
    await store.aclose_all()
    assert len(findings) == 1 and findings[0].type == "security_headers"


@pytest.mark.asyncio
async def test_scan_no_match_yields_nothing():
    tpl = Template(id="none", info=TemplateInfo(name="yok"), type="exposure", path="/actuator/env",
                   matchers=[Matcher(type="word", words=["BU_YOK"])])
    store, det, session = await _detector([tpl])
    findings = await det.scan(session)
    await store.aclose_all()
    assert findings == []


@pytest.mark.asyncio
async def test_scan_runs_repo_templates_without_crash():
    # Depoda sürülen gerçek template'ler ağsız hedefe karşı çökmeden koşar (missing-headers eşleşir).
    templates, _ = load_templates(REPO_TEMPLATES)
    store, det, session = await _detector(templates)
    findings = await det.scan(session)
    await store.aclose_all()
    types = {f.type for f in findings}
    assert "security_headers" in types      # "/" 200 + HSTS/CSP yok → template sürüldü
