.PHONY: demo test bench-guard lint verify eval prove

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

# AS-9: ruff (E,W,F,I,UP,B,SIM — bkz. pyproject.toml [tool.ruff]). Ağsız, hedefsiz.
lint:
	ruff check .

# AS-7: sürüm bütünlüğü — manifest hash · ast-parse · JSON · rapor aritmetiği · yerel linkler.
# Ağsız, import'suz, yalnız stdlib. Kasıtlı değişiklikten sonra: make verify ARGS=--update
verify:
	$(PYTHON) -m scripts.verify_release $(ARGS)

# Çalıştırılabilir self-eval artefaktı (M+A+C+J+R): planted TP + FP + near-miss → precision/recall/
# FP-rate. Ağsız; eval/results.{json,md} üretir; FP>0 ya da near-miss CONFIRMED → çıkış ≠ 0.
eval:
	$(PYTHON) eval/evaluate.py

# F (derece-analizi): tek komutta "HER ŞEYİ KANITLA" — jüri deneyimini kolaylaştırır.
# Ağsız dört kapı: testler (network'süz unit) · self-eval (FP-rate %0) · 0-FP negatif-ikiz ·
# sürüm bütünlüğü (etiket/template tahrifi). İlk kırılan kapıda durur (non-zero exit).
prove:
	$(PYTHON) -m pytest -q
	$(PYTHON) eval/evaluate.py --quiet
	$(PYTHON) -m scripts.bench_guard
	$(PYTHON) -m scripts.verify_release
