"""policy/authorize — saf güvenlik kapısı. DESIGN.md §14."""
from pentestai.models import CapturedRequest, Scope
from pentestai.policy.authorize import Allow, Deny, authorize


def _scope(**kw):
    base = dict(
        allowed_hosts=["localhost", "127.0.0.1"],
        allowed_ports=[3000],
        allowed_path_prefixes=["/api/", "/rest/"],
        denied_path_patterns=["*/admin/db*"],
        allowed_methods=["GET", "HEAD"],
    )
    base.update(kw)
    return Scope(**base)


def _req(url, method="GET", body=None):
    return CapturedRequest(method=method, url=url, body=body)


def test_allow_in_scope():
    assert isinstance(authorize(_req("http://localhost:3000/api/orders/1"), _scope()), Allow)


def test_deny_host_out_of_scope():
    d = authorize(_req("http://evil.example:3000/api/x"), _scope())
    assert isinstance(d, Deny) and "host" in d.reason


def test_deny_port():
    d = authorize(_req("http://localhost:8080/api/x"), _scope())
    assert isinstance(d, Deny) and "port" in d.reason


def test_deny_method():
    d = authorize(_req("http://localhost:3000/api/x", method="DELETE"), _scope())
    assert isinstance(d, Deny) and "method" in d.reason


def test_deny_path_prefix():
    d = authorize(_req("http://localhost:3000/secret/x"), _scope())
    assert isinstance(d, Deny) and "path" in d.reason


def test_deny_denied_pattern():
    d = authorize(_req("http://localhost:3000/api/admin/db-reset"), _scope())
    assert isinstance(d, Deny) and "path" in d.reason


def test_deny_secret_in_query():
    d = authorize(_req("http://localhost:3000/api/x?token=abc123"), _scope())
    assert isinstance(d, Deny) and "secret" in d.reason


def test_ip_pin_blocks_metadata():
    d = authorize(_req("http://localhost:3000/api/x"), _scope(),
                  pin_map={"localhost": "169.254.169.254"})
    assert isinstance(d, Deny) and "ip" in d.reason


def test_ip_pin_allows_loopback():
    d = authorize(_req("http://localhost:3000/api/x"), _scope(),
                  pin_map={"localhost": "127.0.0.1"})
    assert isinstance(d, Allow)


def test_deny_payload_too_large():
    d = authorize(_req("http://localhost:3000/api/x", method="HEAD", body=b"x" * 10),
                  _scope(max_payload_bytes=4))
    assert isinstance(d, Deny) and "payload" in d.reason
