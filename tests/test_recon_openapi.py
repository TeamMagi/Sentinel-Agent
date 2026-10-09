"""OpenApiRecon — spec → Endpoint. DESIGN.md §14 (Stage 1)."""
from pentestai.recon import OpenApiRecon

SPEC = {
    "paths": {
        "/api/orders/{orderId}": {"get": {}, "post": {}},
        "/api/users": {"get": {}},
        "/api/admin/config": {"get": {}},
    }
}


def test_parse_discovers_read_endpoints_and_named_id():
    eps = OpenApiRecon().parse(SPEC)
    triples = {(e.method, e.path_template, e.id_param) for e in eps}
    assert ("GET", "/api/orders/{orderId}", "orderId") in triples
    assert ("GET", "/api/users", "id") in triples
    assert ("GET", "/api/admin/config", "id") in triples
    # v0 read-only: POST toplanmaz
    assert all(e.method in ("GET", "HEAD") for e in eps)


def test_named_param_substituted_by_with_id():
    ep = next(e for e in OpenApiRecon().parse(SPEC) if e.path_template.endswith("{orderId}"))
    req = ep.with_id("42", "http://localhost:3000")
    assert req.url == "http://localhost:3000/api/orders/42"


def test_has_id_flag():
    eps = {e.path_template: e for e in OpenApiRecon().parse(SPEC)}
    assert eps["/api/orders/{orderId}"].has_id is True
    assert eps["/api/users"].has_id is False


# --- #2: kullanıcı-kapsamlı query parametreleri → query-BOLA otomatik keşfi ---

SPEC_QUERY = {
    "paths": {
        # operasyon-seviyesi query param'ları: userId BOLA adayı, limit değil
        "/api/orders": {"get": {"parameters": [
            {"name": "userId", "in": "query"}, {"name": "limit", "in": "query"}]}},
        # path-seviyesi param (item.parameters) — account_id BOLA adayı
        "/api/report": {"parameters": [{"name": "account_id", "in": "query"}], "get": {}},
        # BOLA-kapsamlı olmayan query param → query endpoint üretilmez
        "/api/search": {"get": {"parameters": [{"name": "q", "in": "query"}]}},
    }
}


def test_query_scoped_param_becomes_query_bola_candidate():
    eps = OpenApiRecon().parse(SPEC_QUERY)
    quads = {(e.method, e.path_template, e.id_param, e.id_location) for e in eps}
    assert ("GET", "/api/orders", "userId", "query") in quads      # userId → query-BOLA
    assert ("GET", "/api/report", "account_id", "query") in quads  # path-seviyesi param da
    # "limit" ve "q" kullanıcı-kapsamlı değil → query endpoint YOK
    assert not any(e.id_param in ("limit", "q") for e in eps)


def test_query_bola_endpoint_has_id_and_builds_query_url():
    ep = next(e for e in OpenApiRecon().parse(SPEC_QUERY)
              if e.path_template == "/api/orders" and e.id_location == "query")
    assert ep.has_id is True                                       # planner idor hipotezi üretir
    assert ep.with_id("A-100", "http://t").url == "http://t/api/orders?userId=A-100"


def test_no_duplicate_endpoints():
    eps = OpenApiRecon().parse(SPEC_QUERY)
    keys = [(e.method, e.path_template, e.id_param, e.id_location) for e in eps]
    assert len(keys) == len(set(keys))                             # dedupe çalışıyor


SPEC_HEADER = {
    "paths": {
        "/api/account": {"get": {"parameters": [
            {"name": "X-Account-Id", "in": "header"},               # kullanıcı-kapsamlı → header-BOLA
            {"name": "Accept", "in": "header"}]}},                  # generic → aday değil
    }
}


def test_user_scoped_header_becomes_header_bola_candidate():
    eps = OpenApiRecon().parse(SPEC_HEADER)
    quads = {(e.method, e.path_template, e.id_param, e.id_location) for e in eps}
    assert ("GET", "/api/account", "X-Account-Id", "header") in quads
    assert not any(e.id_param == "Accept" for e in eps)            # generic header aday değil
