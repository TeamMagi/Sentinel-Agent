"""MarkerExtractor — leaked-marker çıkarımı (JSON + HTML/text). DESIGN.md §10.6.

P2 recall düzeltmesi: JSON olmayan (HTML/text) cevaplarda yalnızca email değil, yüksek-sinyalli
yapısal PII (IBAN/kart/SSN/JWT) da marker havuzuna girer → HTML render eden hedeflerde IDOR kaçmaz.
"""
from pentestai.net.normalize import ResponseNormalizer
from pentestai.oracle.markers import MarkerExtractor


def _html(body: str):
    n = ResponseNormalizer()
    return n.normalize_parts(200, {"content-type": "text/html"}, body.encode("utf-8"))


def _json(payload: bytes):
    n = ResponseNormalizer()
    return n.normalize_parts(200, {"content-type": "application/json"}, payload)


def test_html_extracts_email_and_structural_pii():
    resp = _html("<div>Sipariş sahibi: victim@test.local · IBAN: TR330006100519786457841326</div>")
    markers = MarkerExtractor().extract(resp)
    assert "victim@test.local" in markers
    assert "TR330006100519786457841326" in markers


def test_html_extracts_card_and_ssn():
    resp = _html("<p>Kart: 4111 1111 1111 1111</p><p>SSN: 123-45-6789</p>")
    markers = MarkerExtractor().extract(resp)
    assert "4111 1111 1111 1111" in markers
    assert "123-45-6789" in markers


def test_json_string_values_also_scanned():
    resp = _json(b'{"note": "iletisim: victim@test.local"}')
    markers = MarkerExtractor().extract(resp)
    assert "victim@test.local" in markers


def test_no_false_marker_from_plain_html():
    resp = _html("<html><body><h1>Hosgeldiniz</h1></body></html>")
    assert MarkerExtractor().extract(resp) == []
