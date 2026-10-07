"""HarRecon — HAR → Endpoint. DESIGN.md §14 (Stage 1)."""
from pentestai.recon import HarRecon


def _entry(method, url, mime="application/json"):
    return {"request": {"method": method, "url": url}, "response": {"content": {"mimeType": mime}}}


HAR = {"log": {"entries": [
    _entry("GET", "http://localhost:3000/api/orders/123"),
    _entry("GET", "http://localhost:3000/api/orders/456"),                       # dedupe → tek
    _entry("GET", "http://localhost:3000/api/users/507f1f77bcf86cd799439011"),   # mongo id
    _entry("GET", "http://localhost:3000/api/sessions/550e8400-e29b-41d4-a716-446655440000"),  # uuid
    _entry("GET", "http://localhost:3000/api/health"),                           # id yok
    _entry("GET", "http://localhost:3000/main.js", mime="application/javascript"),  # statik → elenir
    _entry("POST", "http://localhost:3000/api/orders"),                          # yazma → elenir
    _entry("GET", "https://analytics.example/collect/9"),                        # 3. parti host
]}}


def _triples(eps):
    return {(e.method, e.path_template) for e in eps}


def test_templatizes_and_dedupes_ids():
    eps = HarRecon().parse(HAR, allowed_hosts=["localhost"])
    t = _triples(eps)
    assert ("GET", "/api/orders/{id}") in t
    assert ("GET", "/api/users/{id}") in t         # mongo id şablonlandı
    assert ("GET", "/api/sessions/{id}") in t      # uuid şablonlandı
    assert ("GET", "/api/health") in t
    # orders iki kez görüldü ama tek endpoint
    assert sum(1 for e in eps if e.path_template == "/api/orders/{id}") == 1


def test_filters_static_write_and_foreign_host():
    eps = HarRecon().parse(HAR, allowed_hosts=["localhost"])
    paths = {e.path_template for e in eps}
    assert "/main.js" not in paths                 # JSON değil → elendi
    assert not any(e.method == "POST" for e in eps)  # read-only
    assert "/collect/{id}" not in paths            # host allowlist dışı


def test_with_id_on_har_endpoint():
    ep = next(e for e in HarRecon().parse(HAR, allowed_hosts=["localhost"])
              if e.path_template == "/api/orders/{id}")
    assert ep.with_id("42", "http://localhost:3000").url == "http://localhost:3000/api/orders/42"
    assert ep.resource_key == "orders"
