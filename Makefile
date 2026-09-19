.PHONY: demo test

# Tek komutluk demo: Juice Shop'u ayağa kaldır, kalibrasyon hesaplarını hazırla,
# taramayı koş ve kanıtlı CONFIRMED bulguyu içeren HTML raporu üret.
demo:
	bash scripts/demo.sh

test:
	docker compose run --rm sentinel pytest -q
