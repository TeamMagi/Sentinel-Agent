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
