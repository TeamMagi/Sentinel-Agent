"""PolicyEngine — saf güvenlik kapısı. DESIGN.md §14."""
from pentestai.models import CapturedRequest, Scope
from pentestai.policy import Allow, Deny, PolicyEngine


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


def _authz(url, scope=None, pin_map=None, **req_kw):
    return PolicyEngine(scope or _scope(), pin_map).authorize(_req(url, **req_kw))


def test_allow_in_scope():
    assert isinstance(_authz("http://localhost:3000/api/orders/1"), Allow)


def test_deny_host_out_of_scope():
    d = _authz("http://evil.example:3000/api/x")
    assert isinstance(d, Deny) and "host" in d.reason


def test_deny_port():
    d = _authz("http://localhost:8080/api/x")
    assert isinstance(d, Deny) and "port" in d.reason


def test_deny_method():
    d = _authz("http://localhost:3000/api/x", method="DELETE")
    assert isinstance(d, Deny) and "method" in d.reason


def test_deny_path_prefix():
    d = _authz("http://localhost:3000/secret/x")
    assert isinstance(d, Deny) and "path" in d.reason


def test_deny_denied_pattern():
    d = _authz("http://localhost:3000/api/admin/db-reset")
    assert isinstance(d, Deny) and "path" in d.reason


def test_deny_secret_in_query():
    d = _authz("http://localhost:3000/api/x?token=abc123")
    assert isinstance(d, Deny) and "secret" in d.reason


def test_ip_pin_blocks_metadata():
    d = _authz("http://localhost:3000/api/x", pin_map={"localhost": "169.254.169.254"})
    assert isinstance(d, Deny) and "ip" in d.reason


def test_ip_pin_allows_loopback():
    d = _authz("http://localhost:3000/api/x", pin_map={"localhost": "127.0.0.1"})
    assert isinstance(d, Allow)


def test_deny_payload_too_large():
    d = _authz("http://localhost:3000/api/x", scope=_scope(max_payload_bytes=4),
               method="HEAD", body=b"x" * 10)
    assert isinstance(d, Deny) and "payload" in d.reason


def test_deny_destructive_when_flag_off():
    # allowed_methods yıkıcı method'u içerse bile destructive_tests=False ise blok (§5, iki katmanlı kapı)
    scope = _scope(allowed_methods=["GET", "HEAD", "PUT", "DELETE"], destructive_tests=False)
    d = _authz("http://localhost:3000/api/orders/1", scope=scope, method="DELETE")
    assert isinstance(d, Deny) and "destructive" in d.reason


def test_allow_destructive_when_flag_on():
    scope = _scope(allowed_methods=["GET", "HEAD", "PUT", "DELETE"], destructive_tests=True)
    d = _authz("http://localhost:3000/api/orders/1", scope=scope, method="DELETE")
    assert isinstance(d, Allow)


def test_safe_methods_unaffected_by_destructive_flag():
    d = _authz("http://localhost:3000/api/orders/1", scope=_scope(destructive_tests=False))
    assert isinstance(d, Allow)
