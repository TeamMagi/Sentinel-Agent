.PHONY: demo test bench-guard verify

# Yorumlayıcı: yerel .venv varsa onu, yoksa python3'ü kullan (bazı sistemlerde `python` YOKTUR).
# Elle geçersiz kılmak için: make bench-guard PYTHON=/usr/bin/python3.11
PYTHON ?= $(shell test -x .venv/bin/python && echo .venv/bin/python || echo python3)

# Tek komutluk demo: Juice Shop'u ayağa kaldır, kalibrasyon hesaplarını hazırla,
# taramayı koş ve kanıtlı CONFIRMED bulguyu içeren HTML raporu üret.
demo:
	bash scripts/demo.sh

test:
	docker compose run --rm sentinel pytest -q

# RK-10: 0-FP negatif-ikiz regresyon kapısı — hardened ikizde yanlış CONFIRMED çıkarsa kırmızı.
# Ağ yok; kendi pipeline'ınızda "FP hâlâ 0 mı?" diye koşun.
bench-guard:
	$(PYTHON) -m scripts.bench_guard

# AS-7: sürüm bütünlüğü — manifest hash · ast-parse · JSON · rapor aritmetiği · yerel linkler.
# Ağsız, import'suz, yalnız stdlib. Kasıtlı değişiklikten sonra: make verify ARGS=--update
verify:
	$(PYTHON) -m scripts.verify_release $(ARGS)
