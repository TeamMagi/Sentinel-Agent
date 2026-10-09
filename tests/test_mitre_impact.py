"""MITRE ATT&CK eşlemesi (T) + bağlamsal blast-radius (S). Ağsız, deterministik."""
from __future__ import annotations

from pentestai.classify import DEFAULT_MITRE, assign, mitre_for
from pentestai.models import Finding
from pentestai.report.impact import impact_context
from pentestai.report.render_md import MarkdownReporter


def _f(vtype: str, verdict: str = "CONFIRMED", **kw) -> Finding:
    return Finding(id="F-1", type=vtype, endpoint="/api/x/{id}", verdict=verdict, **kw)


# --- T: MITRE ---

def test_mitre_default_umbrella_for_access_control():
    assert mitre_for("idor") == DEFAULT_MITRE          # T1190 umbrella
    assert mitre_for("bola") == DEFAULT_MITRE


def test_mitre_specific_techniques():
    assert mitre_for("exfiltration").startswith("T1041")
    assert mitre_for("command_injection").startswith("T1059")
    assert mitre_for("default_credentials").startswith("T1078")


def test_assign_sets_mitre_deterministically():
    f = assign(_f("exfiltration"))
    assert f.mitre.startswith("T1041")
    assert assign(_f("exfiltration")).mitre == f.mitre     # idempotent/deterministik


def test_report_shows_mitre():
    out = MarkdownReporter().render([assign(_f("idor"))])
    assert "T1190" in out


# --- S: blast-radius ---

def test_impact_cross_user_two_actor():
    ctx = impact_context(_f("idor", victim="user_A", attacker="user_B"))
    assert "çapraz-kullanıcı" in ctx and "iki-aktör" in ctx


def test_impact_write_operation_flagged():
    ctx = impact_context(_f("state_change_authz", method="DELETE"))
    assert "kalıcı değişiklik" in ctx


def test_impact_unauthenticated_surface():
    ctx = impact_context(_f("unauthorized_access"))
    assert "kimlik-doğrulamasız" in ctx


def test_impact_none_for_rejected():
    assert impact_context(_f("idor", verdict="REJECTED")) is None


def test_report_shows_impact_context():
    out = MarkdownReporter().render([_f("idor", victim="user_A", attacker="user_B")])
    assert "Bağlamsal etki (heuristik)" in out
