"""HandleAnonymizer — RK-7 (GOREVLER.md Dalga 3). Redaction'ın üstüne gizlilik katmanı.

Gerçek aktör adı/ham id'nin rapora giden KOPYADA görünmediğini, orijinal `Finding`
listesinin DEĞİŞMEDİĞİNİ ve aynı gerçek değerin her yerde AYNI handle'a çevrildiğini
doğrular. Network yok.
"""
from pentestai.models import Actor, AuthState, CapturedRequest, Evidence, Finding, NormalizedResponse
from pentestai.report.anonymize import HandleAnonymizer


def _finding() -> Finding:
    ev = Evidence(
        baseline_request=CapturedRequest(method="GET", url="http://localhost:3000/api/orders/A-100"),
        baseline_response=NormalizedResponse(
            status=200, body_text='{"id": "A-100", "owner": "user_A"}',
            body_normalized='{"id": "A-100", "owner": "user_A"}',
            json_body={"id": "A-100", "owner": "user_A"}),
        attack_request=CapturedRequest(method="GET", url="http://localhost:3000/api/orders/A-100"),
        attack_response=NormalizedResponse(
            status=200, body_text='{"id": "A-100", "owner": "user_A"}',
            body_normalized='{"id": "A-100", "owner": "user_A"}',
            json_body={"id": "A-100", "owner": "user_A"}),
        leaked_markers=["a@test.local"],
        repro_curl='curl -H "Authorization: Bearer <USER_B_TOKEN>" http://localhost:3000/api/orders/A-100',
    )
    return Finding(id="F-001", type="idor", endpoint="/api/orders/A-100", verdict="CONFIRMED",
                   confidence="high", victim="user_A", attacker="user_B",
                   found_as="user_B", victim_as="user_A", evidence=ev)


def test_actor_names_replaced_with_stable_identity_handles():
    anon = HandleAnonymizer()
    [g] = anon.anonymize_findings([_finding()])
    assert g.victim == "identity-1" and g.attacker == "identity-2"
    assert g.found_as == "identity-2" and g.victim_as == "identity-1"
    # aynı gerçek isim HER YERDE aynı handle'a çevrilir
    assert "user_A" not in g.evidence.baseline_response.body_text
    assert "identity-1" in g.evidence.baseline_response.body_text


def test_known_object_id_replaced_in_url_and_body():
    anon = HandleAnonymizer()
    anon.register_known_ids([
        Actor(name="user_A", auth=AuthState(), own_object_ids={"order": "A-100"}),
    ])
    [g] = anon.anonymize_findings([_finding()])
    assert "A-100" not in g.evidence.baseline_request.url
    assert "A-100" not in g.evidence.baseline_response.body_text
    assert "A-100" not in g.evidence.repro_curl
    assert g.endpoint.startswith("/api/orders/obj-")


def test_original_finding_is_not_mutated():
    original = _finding()
    HandleAnonymizer().anonymize_findings([original])
    assert original.victim == "user_A"
    assert "user_A" in original.evidence.baseline_response.body_text
    assert "A-100" in original.evidence.baseline_request.url


def test_registered_known_ids_get_consistent_handle_even_if_unseen_in_finding():
    anon = HandleAnonymizer()
    anon.register_known_ids([
        Actor(name="user_A", auth=AuthState(), own_object_ids={"order": "A-100"}),
    ])
    handle_before = anon.id_handle("A-100")
    [g] = anon.anonymize_findings([_finding()])
    assert handle_before in g.evidence.baseline_request.url


def test_short_numeric_id_does_not_corrupt_unrelated_numbers():
    # id="1" gibi kısa bir değer, alakasız "12345" gibi bir sayının İÇİNDE yanlışlıkla eşleşmemeli.
    anon = HandleAnonymizer()
    anon.id_handle("1")
    text = anon._replace("port 12345 and /orders/1 and total=12345")
    assert "12345" in text                 # bozulmadı
    assert "/orders/1" not in text         # gerçek sınırlı eşleşme değiştirildi
