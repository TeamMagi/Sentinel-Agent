#!/usr/bin/env bash
# Tek komutluk demo: Juice Shop'u ayağa kaldır, kalibrasyon hesaplarını hazırla,
# taramayı koş ve kanıtlı CONFIRMED bulguyu içeren HTML raporu üret.
# Kullanım: bash scripts/demo.sh   (repo kökünden, Docker + docker-compose kurulu olmalı)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

docker compose up -d juice-shop
docker compose run --rm sentinel python -m scripts.bootstrap_demo
docker compose run --rm sentinel python -m scripts.run_scan \
    --scope runs/demo/config/scope.yaml \
    --actors runs/demo/config/actors.yaml \
    --endpoints runs/demo/config/endpoints.yaml \
    --mode active --no-bootstrap --out runs/

echo ""
echo "Rapor hazır: yukarıdaki [done] satırındaki runs/<run-id>/report.html dosyasını tarayıcıda aç."
