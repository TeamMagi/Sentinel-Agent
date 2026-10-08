.PHONY: demo test bench-guard lint

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

# AS-9: ruff (E,W,F,I,UP,B,SIM — bkz. pyproject.toml [tool.ruff]). Ağsız, hedefsiz.
lint:
	ruff check .
