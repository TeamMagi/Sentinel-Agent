"""redact() + tüm çıktı sink'leri — §5.5 (PII/sır ham yazılmaz) regresyon testleri.

Kapsam: değer-desenleri (e-posta/IBAN/kart/TCKN/hash/JWT), anahtar-duyarlı PII maskeleme
(isim/adres gibi desenle yakalanamayan serbest-metin alanlar), AUTH header birliği
(models.AUTH_HEADER_NAMES tek kaynak), aşırı-redaction'a karşı koruma, ve uçtan uca
sink'ler (findings.json, JsonReporter, MarkdownReporter).
"""
import json

import pytest

from pentestai.evidence.store import EvidenceStore, redact
from pentestai.models import CapturedRequest, Evidence, Finding, NormalizedResponse
from pentestai.report import JsonReporter, MarkdownReporter


def _finding_with_body(body_dict: dict) -> Finding:
    body_text = json.dumps(body_dict, ensure_ascii=False)
    resp = NormalizedResponse(status=200, body_text=body_text, json_body=body_dict)
    return Finding(
        id="F-001", type="excessive_data_exposure", endpoint="/api/users/1", method="GET",
        verdict="CONFIRMED", confidence="high",
        evidence=Evidence(baseline_request=CapturedRequest(url="http://localhost/api/users/1"),
                           baseline_response=resp),
    )


# --- (a) değer-desenleri ---

def test_email_is_redacted():
    out = redact('{"email":"kurban@example.com"}')
    assert "kurban@example.com" not in out
    assert "<REDACTED>" in out


def test_iban_is_redacted():
    out = redact('{"iban":"TR330006100519786457841326"}')
    assert "TR330006100519786457841326" not in out
    assert "<REDACTED>" in out


def test_card_number_is_redacted_plain_and_grouped():
    plain = redact('{"card":"4111111111111111"}')
    grouped = redact('{"card":"4111 1111 1111 1111"}')
    dashed = redact('{"card":"4111-1111-1111-1111"}')
    assert "4111111111111111" not in plain
    assert "4111 1111 1111 1111" not in grouped
    assert "4111-1111-1111-1111" not in dashed
    for out in (plain, grouped, dashed):
        assert "<REDACTED>" in out


def test_tckn_is_redacted():
    out = redact('{"tckn":"12345678901"}')
    assert "12345678901" not in out
    assert "<REDACTED>" in out


def test_bcrypt_hash_is_redacted():
    secret = "$2a$10$" + "A" * 53
    out = redact(json.dumps({"passwordHash": secret}))
    assert secret not in out
    assert "<REDACTED>" in out


def test_jwt_is_redacted():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    out = redact(f"token seen: {jwt}")
    assert jwt not in out
    assert "<REDACTED>" in out


# --- (b) anahtar-duyarlı: serbest-metin isim/adres ---

def test_name_field_is_redacted_even_without_value_pattern():
    out = redact(json.dumps({"id": "U1", "name": "Ayse Yilmaz"}))
    assert "Ayse Yilmaz" not in out
    assert '"name"' in out                 # anahtar korunur, sadece değer maskelenir
    assert "<REDACTED>" in out


def test_name_field_is_redacted_in_escaped_body_text():
    # body_text bir STRING alan olduğundan dış json.dumps kaçırır: \"name\":\"...\"
    inner = json.dumps({"id": "U1", "name": "Ayse Yilmaz"})
    outer = json.dumps({"body_text": inner})
    out = redact(outer)
    assert "Ayse Yilmaz" not in out
    assert "<REDACTED>" in out


def test_name_value_with_escaped_quotes_stays_valid_json():
    # regresyon: içinde kaçışlı tırnak geçen değer (ör. ürün adı) redaction sonrası
    # JSON'u BOZMAMALI — eskiden ilk \" karakterinde kesilip geçersiz JSON üretiyordu.
    payload = json.dumps({"id": 41, "name": 'OWASP Juice Shop "Permafrost" 2020 Edition'})
    out = redact(payload)
    parsed = json.loads(out)              # bozuk olsaydı burada patlardı
    assert parsed["name"] == "<REDACTED>"
    assert parsed["id"] == 41
    assert "Permafrost" not in out         # değer tamamen maskelendi (kalıntı yok)


# --- aşırı-redaction'a karşı koruma ---

def test_small_numbers_and_plain_text_are_not_touched():
    payload = json.dumps({
        "llm_calls": 4, "tokens": 1234, "wall_sec": 7.5, "count": 9,
        "proposed_action": "RunOracle idor",
    })
    out = redact(payload)
    assert out == payload   # hiçbir şey değişmemeli


# --- AUTH header birliği (Bug 2) ---

def test_x_auth_token_and_x_csrf_token_headers_are_redacted():
    out = redact('{"x-auth-token":"abc123","x-csrf-token":"def456"}')
    assert "abc123" not in out
    assert "def456" not in out
    assert out.count("<REDACTED>") == 2


# --- uçtan uca sink'ler ---

def test_json_reporter_redacts_full_response_body():
    f = _finding_with_body({
        "id": "U1", "email": "kurban@example.com", "iban": "TR330006100519786457841326",
        "creditCard": "4111111111111111", "name": "Ayse Yilmaz", "passwordHash": "$2a$10$" + "x" * 53,
    })
    out = JsonReporter().render([f])
    for secret in ("kurban@example.com", "TR330006100519786457841326",
                   "4111111111111111", "Ayse Yilmaz"):
        assert secret not in out


def test_findings_json_sink_redacts_full_response_body():
    f = _finding_with_body({
        "id": "U1", "email": "kurban@example.com", "iban": "TR330006100519786457841326",
        "creditCard": "4111111111111111", "name": "Ayse Yilmaz",
    })
    out = EvidenceStore._findings_json([f])
    for secret in ("kurban@example.com", "TR330006100519786457841326",
                   "4111111111111111", "Ayse Yilmaz"):
        assert secret not in out


def test_markdown_reporter_redacts_leaked_markers():
    f = Finding(
        id="F-003", type="idor", endpoint="/api/orders/3", method="GET",
        verdict="CONFIRMED", confidence="high",
        evidence=Evidence(leaked_markers=["kurban@example.com"]),
    )
    out = MarkdownReporter().render([f])
    assert "kurban@example.com" not in out
    assert "<REDACTED>" in out


# --- run_id çakışması (aynı saniyede başlayan iki tarama birbirinin evidence'ını EZMEMELİ) ---

def test_new_run_id_unique_within_same_second():
    ids = {EvidenceStore.new_run_id() for _ in range(50)}
    assert len(ids) == 50


def test_save_run_does_not_overwrite_existing_run_dir(tmp_path):
    store = EvidenceStore(str(tmp_path))
    run_id = "run-20260101-000000-abc123"
    store.save_run(run_id, [])
    with pytest.raises(FileExistsError):
        store.save_run(run_id, [])
