"""ResponseNormalizer — karşılaştırılabilirlik (liste sıralama + volatile scrub). DESIGN.md §10.4.

P2 recall düzeltmesi: sunucunun SIRASIZ döndürdüğü listeler baseline'ı kararsız yapıp gerçek
bulguyu INCONCLUSIVE'e düşürmemeli. Normalizer liste elemanlarını kanonik sıraya koyar.
"""
import json

from pentestai.net.normalize import ResponseNormalizer


def _norm(payload):
    n = ResponseNormalizer()
    body = json.dumps(payload).encode("utf-8")
    return n.normalize_parts(200, {"content-type": "application/json"}, body)


def test_list_order_does_not_break_stability():
    """Aynı içerik, farklı liste sırası → AYNI body_normalized (baseline kararlı kalır)."""
    a = _norm({"orders": [{"id": "1"}, {"id": "2"}, {"id": "3"}]})
    b = _norm({"orders": [{"id": "3"}, {"id": "1"}, {"id": "2"}]})
    assert a.body_normalized == b.body_normalized


def test_scalar_list_order_normalized():
    a = _norm({"tags": ["z", "a", "m"]})
    b = _norm({"tags": ["a", "m", "z"]})
    assert a.body_normalized == b.body_normalized


def test_genuine_content_difference_still_visible():
    """Sıralama sinyali kaldırır ama İÇERİK farkını gizlemez — farklı eleman → farklı normalized."""
    a = _norm({"orders": [{"id": "1"}, {"id": "2"}]})
    b = _norm({"orders": [{"id": "1"}, {"id": "9"}]})
    assert a.body_normalized != b.body_normalized


def test_volatile_key_value_scrubbed():
    """Volatile anahtarların DEĞERİ maskelenir → timestamp farkı baseline'ı kararsız yapmaz."""
    a = _norm({"id": "1", "lastLogin": "2026-01-01T00:00:00Z"})
    b = _norm({"id": "1", "lastLogin": "2026-09-28T12:00:00Z"})
    assert a.body_normalized == b.body_normalized
    assert "<volatile>" in a.body_normalized


def test_marker_value_survives_normalization():
    """Kritik: leaked-marker olabilecek normal değerler (email/id) body_normalized'da KORUNUR —
    değer-seviyesi scrub bilinçli olarak yapılmadı (aksi halde IDOR'da false-negative)."""
    r = _norm({"id": "42", "email": "victim@test.local"})
    assert "victim@test.local" in r.body_normalized
    assert "42" in r.body_normalized
