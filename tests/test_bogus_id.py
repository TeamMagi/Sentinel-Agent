"""bogus_id_like — biçim-uyumlu var-olmayan id üretimi (negatif kontrol). DESIGN.md §10.6.

P2 recall düzeltmesi: UUID id'li endpoint'e tip-uyumsuz sayısal bogus göndermek 400 (validation)
döndürüp negatif kontrolü kırabiliyordu. bogus, kurbanın id BİÇİMİNE uyar.
"""
import re

from pentestai.oracle.base import bogus_id_like

_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def test_uuid_sample_yields_valid_uuid_shape():
    out = bogus_id_like("2b1e7c9a-1234-4abc-8def-0123456789ab")
    assert _UUID.match(out)                       # biçim korunur → 404, 400 değil


def test_pure_numeric_sample():
    assert bogus_id_like("100").isdigit()


def test_prefixed_numeric_preserves_prefix():
    out = bogus_id_like("A-100")
    assert out.startswith("A-") and out[2:].isdigit()


def test_alphanumeric_sample_stays_nonempty():
    assert bogus_id_like("abc") and bogus_id_like("abc") != "abc"


def test_none_and_empty_fallback():
    assert bogus_id_like(None) == "999999999"
    assert bogus_id_like("") == "999999999"
