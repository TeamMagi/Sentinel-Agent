"""scripts/pr_comment.py — findings.json'ı PR yorumu Markdown'ına çevirir (CI baseline-diff)."""
from scripts.pr_comment import MARKER, render


def _f(fid, vtype, verdict, *, baseline_status=None, severity=None, endpoint="/api/x", method="GET"):
    return {
        "id": fid, "type": vtype, "verdict": verdict, "baseline_status": baseline_status,
        "severity": severity, "endpoint": endpoint, "method": method,
    }


def test_no_new_findings_when_all_known():
    body = render([_f("F-001", "idor", "CONFIRMED", baseline_status="known")])
    assert MARKER in body
    assert "bulgu yok" in body


def test_no_new_findings_when_only_rejected_or_inconclusive():
    body = render([
        _f("F-001", "idor", "REJECTED"),
        _f("F-002", "bfla", "INCONCLUSIVE"),
    ])
    assert "bulgu yok" in body


def test_lists_new_confirmed_finding():
    body = render([_f("F-003", "idor", "CONFIRMED", severity="high", endpoint="/api/orders/{id}")])
    assert "1 yeni bulgu" in body
    assert "F-003" in body and "idor" in body and "/api/orders/{id}" in body


def test_known_finding_excluded_but_new_one_included():
    body = render([
        _f("F-001", "idor", "CONFIRMED", baseline_status="known"),
        _f("F-002", "bfla", "LIKELY", baseline_status="new"),
    ])
    assert "1 yeni bulgu" in body
    assert "F-002" in body
    assert "F-001" not in body


def test_sorted_by_severity_then_id():
    body = render([
        _f("F-002", "bfla", "CONFIRMED", severity="low"),
        _f("F-001", "idor", "CONFIRMED", severity="critical"),
    ])
    assert body.index("F-001") < body.index("F-002")
