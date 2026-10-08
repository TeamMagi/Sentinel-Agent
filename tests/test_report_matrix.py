"""2×2 yetki matrisi (R-B1) — gruplama, horizontal/vertical, asimetrik izolasyon. Network yok."""
from pentestai.models import Finding
from pentestai.report.matrix import AuthMatrixReporter, build_auth_matrix

ROLES = {"user_A": "user", "user_B": "user", "admin": "admin"}


def _f(type_, endpoint, victim, attacker, verdict):
    return Finding(id="F", type=type_, endpoint=endpoint, verdict=verdict,
                   victim=victim, attacker=attacker)


def test_matrix_groups_and_detects_asymmetric_isolation():
    findings = [
        _f("idor", "/api/orders/{id}", "user_A", "user_B", "CONFIRMED"),  # B, A'nınkini okuyor
        _f("idor", "/api/orders/{id}", "user_B", "user_A", "REJECTED"),   # ters yön kapalı
    ]
    m = build_auth_matrix(findings, ROLES)
    assert len(m) == 1
    g = m[0]
    assert g["type"] == "idor" and g["endpoint"] == "/api/orders/{id}"
    assert ("user_A", "user_B") in g["leaks"]
    assert g["asymmetric"] == [("user_A", "user_B")]           # tek yön sızıyor
    assert g["cells"][("user_A", "user_B")]["escalation"] == "horizontal"  # aynı rol


def test_matrix_marks_vertical_when_roles_differ():
    findings = [_f("bfla", "/api/admin/users", "admin", "user_A", "CONFIRMED")]
    g = build_auth_matrix(findings, ROLES)[0]
    assert g["cells"][("admin", "user_A")]["escalation"] == "vertical"     # rol farkı


def test_matrix_ignores_findings_without_actor_labels():
    findings = [_f("idor", "/x", None, None, "CONFIRMED"),
                Finding(id="F", type="cors", endpoint="/y", verdict="CONFIRMED")]
    assert build_auth_matrix(findings, ROLES) == []


def test_reporter_renders_table_and_asymmetry():
    findings = [
        _f("idor", "/api/orders/{id}", "user_A", "user_B", "CONFIRMED"),
        _f("idor", "/api/orders/{id}", "user_B", "user_A", "REJECTED"),
    ]
    md = AuthMatrixReporter().render(findings, ROLES)
    assert "Yetki Matrisi" in md
    assert "user_A" in md and "user_B" in md
    assert "asimetrik izolasyon" in md
    assert "🔴" in md   # CONFIRMED sembolü


def test_reporter_empty_when_no_two_actor_findings():
    assert AuthMatrixReporter().render([], ROLES) == ""
