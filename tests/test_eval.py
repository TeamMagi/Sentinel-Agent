"""Çalıştırılabilir self-eval artefaktının ağsız doğrulaması (M+A+C+J+R).

Kanıt-vitrini iddiasını (FP-rate %0, near-miss dahil) her PR'da belirlenimci tutar; labeled.json
yer-gerçeği ile katalog arasındaki sürüklenmeyi (drift) yakalar.
"""
from __future__ import annotations

from pentestai.bench.eval import (
    check_consistency, default_cases, load_labeled, run_cases,
)


async def test_zero_false_positive_and_near_miss_discipline():
    """FP-rate %0: negative + near-miss vakalarının HİÇBİRİ yanlış CONFIRMED olmamalı."""
    metrics = await run_cases(default_cases())
    assert metrics.fp == 0, f"yanlış CONFIRMED: {[o.name for o in metrics.outcomes if o.category != 'positive' and o.confirmed]}"
    assert metrics.near_miss_confirmed == []
    assert metrics.fp_rate == 0.0
    assert metrics.clean is True


async def test_planted_true_positives_all_caught():
    """Recall 1.0: planted gerçek açıkların (positive) tamamı CONFIRMED yakalanmalı."""
    metrics = await run_cases(default_cases())
    assert metrics.recall == 1.0, f"kaçırılan: {[o.name for o in metrics.outcomes if o.category == 'positive' and not o.confirmed]}"
    assert metrics.precision == 1.0


def test_labeled_json_matches_catalog():
    """labeled.json ↔ katalog sürüklenmesi (drift) olmamalı."""
    assert check_consistency(default_cases(), load_labeled()) == []


def test_all_three_categories_present():
    """Set planted TP + design-safe + near-miss'in üçünü de içermeli (R disiplini)."""
    cats = {row["category"] for row in load_labeled()}
    assert cats == {"positive", "negative", "near_miss"}
