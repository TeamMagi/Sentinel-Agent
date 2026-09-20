.PHONY: demo test bench-guard

# Tek komutluk demo: Juice Shop'u ayağa kaldır, kalibrasyon hesaplarını hazırla,
# taramayı koş ve kanıtlı CONFIRMED bulguyu içeren HTML raporu üret.
demo:
	bash scripts/demo.sh

test:
	docker compose run --rm sentinel pytest -q

# RK-10: 0-FP negatif-ikiz regresyon kapısı — hardened ikizde yanlış CONFIRMED çıkarsa kırmızı.
# Ağ yok; kendi pipeline'ınızda "FP hâlâ 0 mı?" diye koşun.
bench-guard:
	python -m scripts.bench_guard
