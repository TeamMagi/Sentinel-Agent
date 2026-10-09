"""NucleiIngestor — dış araç (nuclei) çıktısı → Endpoint/Hypothesis. GOREVLER #13.

Ağsız/dosyasız (yalnızca metin ayrıştırma). Kabul: bilinen tag'ler hipoteze çevrilir, bilinmeyen
tag'ler sessizce atlanır, bozuk satırlar taramayı çökertmez, id-benzeri segmentler şablonlanır.
"""
import json

from pentestai.recon import NucleiIngestor
from pentestai.recon.nuclei import TAG_TO_HYPOTHESIS_TYPE, NucleiFinding


def _line(template_id, name, severity, tags, matched_at, cve_id=None):
    return json.dumps({
        "template-id": template_id,
        "info": {"name": name, "severity": severity, "tags": tags,
                 "classification": {"cve-id": cve_id}},
        "matched-at": matched_at,
    })


JSONL = "\n".join([
    _line("exposed-idor", "IDOR check", "high", ["idor", "api"],
          "http://localhost:3000/api/orders/123"),
    _line("cve-2024-0001", "Known CVE", "critical", ["cve", "sqli"],
          "http://localhost:3000/api/search?q=1", cve_id="CVE-2024-0001"),
    _line("no-mapped-tag", "Şablon", "info", ["fingerprint"],
          "http://localhost:3000/api/health"),
    "",           # boş satır → atlanır
    "{ bozuk json",   # bozuk satır → atlanır
    json.dumps({"template-id": "no-matched-at", "info": {"tags": ["idor"]}}),  # matched-at yok → atlanır
])


def test_parse_skips_broken_and_empty_lines():
    findings = NucleiIngestor().parse(JSONL)
    assert len(findings) == 3   # yalnızca geçerli + matched-at'lı 3 satır


def test_parse_extracts_fields():
    findings = NucleiIngestor().parse(JSONL)
    f = findings[0]
    assert f.template_id == "exposed-idor" and f.severity == "high"
    assert f.tags == ("idor", "api")


def test_parse_extracts_cve_id():
    findings = NucleiIngestor().parse(JSONL)
    cve_finding = next(f for f in findings if f.template_id == "cve-2024-0001")
    assert cve_finding.cve_id == "CVE-2024-0001"


def test_to_endpoints_templatizes_and_dedupes():
    findings = NucleiIngestor().parse(JSONL)
    eps = NucleiIngestor().to_endpoints(findings)
    paths = {e.path_template for e in eps}
    assert "/api/orders/{id}" in paths     # sayısal id şablonlandı
    assert "/api/search" in paths
    assert "/api/health" in paths
    assert all(e.method == "GET" for e in eps)


def test_to_hypotheses_maps_known_tags():
    findings = NucleiIngestor().parse(JSONL)
    hyps = NucleiIngestor().to_hypotheses(findings)
    types = {h.type for h in hyps}
    assert "idor" in types        # 'idor' tag'i
    assert "injection" in types   # 'sqli' tag'i (cve satırı da sqli taşıyor)
    # "fingerprint" tag'i haritada yok → o bulgu için hiç hipotez üretilmedi
    assert not any("no-mapped-tag" in h.rationale for h in hyps)


def test_to_hypotheses_cites_template_id_in_rationale():
    findings = NucleiIngestor().parse(JSONL)
    hyps = NucleiIngestor().to_hypotheses(findings)
    assert any("exposed-idor" in h.rationale for h in hyps)
    # nuclei sonucu tek başına kanıt sayılmaz — rationale bunu açıkça belirtir
    assert all("doğrulanacak" in h.rationale for h in hyps)


def test_to_hypotheses_only_first_matching_tag_per_finding():
    finding = NucleiFinding(template_id="t1", name="x", severity="low",
                            tags=("idor", "bola"), matched_at="http://x/api/a/1")
    hyps = NucleiIngestor().to_hypotheses([finding])
    assert len(hyps) == 1   # aynı bulgu için tekrarlı hipotez yok


def test_unknown_tag_map_is_extensible_via_di():
    finding = NucleiFinding(template_id="t1", name="x", severity="low",
                            tags=("my-custom-tag",), matched_at="http://x/api/a")
    custom_map = dict(TAG_TO_HYPOTHESIS_TYPE)
    custom_map["my-custom-tag"] = "cors"
    hyps = NucleiIngestor(tag_map=custom_map).to_hypotheses([finding])
    assert hyps and hyps[0].type == "cors"


def test_parse_accepts_comma_string_tags():
    line = json.dumps({"template-id": "t1", "info": {"tags": "idor,api"}, "matched-at": "http://x/a"})
    findings = NucleiIngestor().parse(line)
    assert findings[0].tags == ("idor", "api")


def test_load_reads_file(tmp_path):
    path = tmp_path / "nuclei.jsonl"
    path.write_text(JSONL, encoding="utf-8")
    findings = NucleiIngestor().load(str(path))
    assert len(findings) == 3
