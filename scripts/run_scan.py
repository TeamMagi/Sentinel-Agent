"""Sentinel-Agent CLI — geriye dönük uyumlu ince kabuk. DESIGN.md §10.12 (R-D3).

Asıl CLI artık **kurulabilir** paket komutu: `pip install .` sonrası `sentinel scan ...`
(bkz. `pentestai/cli.py` — mantığın TEK kaynağı orasıdır; scan modları, bütçe ölçekleme,
tüm bayraklar oradan gelir). Bu dosya, kurulum yapılmadan `python -m scripts.run_scan ...`
ile eski komutu ÇALIŞTIRMAYA devam eder (docker-compose/CI script'leri bozulmasın).

Örnek (endpoint dosyasıyla):
  python -m scripts.run_scan --scope config/scope.yaml --actors config/actors.yaml \
      --endpoints config/endpoints.yaml --mode active --out runs/
Örnek (OpenAPI spec'inden keşif):
  python -m scripts.run_scan --scope config/scope.yaml --actors config/actors.yaml \
      --openapi openapi.json --mode active
  ... --dry-run   # istekleri authorize'dan geçir ama GÖNDERME (plan önizlemesi)
"""
from __future__ import annotations

import pathlib
import sys

# Kurulum yapılmadan da çalışsın diye src'yi path'e ekle.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from pentestai.cli import (  # noqa: E402,F401 (F401: geriye dönük uyumluluk için dışa aktarılır)
    _fail_exit,
    scan_main,
)

main = scan_main

if __name__ == "__main__":
    raise SystemExit(main())
