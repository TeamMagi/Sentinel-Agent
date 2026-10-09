"""PolicyEngine.authorize TRUTH-TABLE (H — NoScam dersi).

`authorize` deterministik bir kapıdır; her giriş kombinasyonu → tek bir karar. Ayrı ayrı test
edilen yolları TEK bir belgelenmiş tabloda toplar (kararın sırası + her Deny gerekçesi). Tablo
hem doküman hem çalıştırılabilir sözleşmedir — DESIGN.md §"Policy truth-table" ile aynı satırlar.

Karar sırası (fail-closed): host → (pin/rebind) → port → method → destructive → path(prefix/deny)
→ secret-in-query → payload → ALLOW.
"""
from __future__ import annotations

import pytest

from pentestai.models import CapturedRequest, Scope
from pentestai.policy import Allow, Deny, PolicyEngine


def _scope(**kw) -> Scope:
    base = dict(
        allowed_hosts=["localhost"], allowed_ports=[3000],
        allowed_path_prefixes=["/api/", "/rest/"], denied_path_patterns=["*/admin/db*"],
        allowed_methods=["GET", "HEAD"], destructive_tests=False, max_payload_bytes=1024,
    )
    base.update(kw)
    return Scope(**base)


# (ad, url, method, body, scope_kwargs, pin_map, purpose, beklenen_deny_substring | None=Allow)
TRUTH_TABLE = [
    ("allow-in-scope",       "http://localhost:3000/api/orders/1", "GET",    None, {}, None, "test", None),
    ("deny-host",            "http://evil:3000/api/x",             "GET",    None, {}, None, "test", "host"),
    ("deny-port",            "http://localhost:8080/api/x",        "GET",    None, {}, None, "test", "port"),
    ("deny-method",          "http://localhost:3000/api/x",        "DELETE", None, {}, None, "test", "method"),
    ("deny-destructive",     "http://localhost:3000/api/x",        "POST",   None,
     {"allowed_methods": ["GET", "POST"], "destructive_tests": False}, None, "test", "destructive"),
    ("allow-destructive-on", "http://localhost:3000/api/x",        "POST",   None,
     {"allowed_methods": ["GET", "POST"], "destructive_tests": True}, None, "test", None),
    ("deny-path-prefix",     "http://localhost:3000/public/x",     "GET",    None, {}, None, "test", "path"),
    ("deny-denied-pattern",  "http://localhost:3000/api/admin/db", "GET",    None, {}, None, "test", "path"),
    ("deny-secret-in-query", "http://localhost:3000/api/x?token=abc", "GET", None, {}, None, "test", "secret"),
    ("deny-payload",         "http://localhost:3000/api/x",        "GET",    b"A" * 2048, {}, None, "test", "payload"),
    ("deny-pin-rebind",      "http://localhost:3000/api/x",        "GET",    None, {},
     {"localhost": "169.254.169.254"}, "test", "ip"),
    ("auth-purpose-allows-post", "http://localhost:3000/rest/user/login", "POST", None, {}, None, "auth", None),
]


@pytest.mark.parametrize("case", TRUTH_TABLE, ids=[c[0] for c in TRUTH_TABLE])
def test_authorize_truth_table(case):
    name, url, method, body, scope_kw, pin_map, purpose, expected = case
    decision = PolicyEngine(_scope(**scope_kw), pin_map).authorize(
        CapturedRequest(method=method, url=url, body=body), purpose=purpose)
    if expected is None:
        assert isinstance(decision, Allow), f"{name}: ALLOW beklendi, {decision} geldi"
    else:
        assert isinstance(decision, Deny), f"{name}: DENY beklendi, {decision} geldi"
        assert expected in decision.reason, f"{name}: gerekçe '{expected}' içermeli: {decision.reason}"


def test_truth_table_covers_every_deny_reason():
    """Tablo, authorize'ın ürettiği TÜM Deny gerekçe ailelerini kapsamalı (eksik yol kalmasın)."""
    covered = {c[7] for c in TRUTH_TABLE if c[7] is not None}
    assert covered == {"host", "port", "method", "destructive", "path", "secret", "payload", "ip"}
