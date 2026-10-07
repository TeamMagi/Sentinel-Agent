"""Sentinel-Agent Web UI sunucusu (ince katman → WebServer). CLAUDE.md §9.

Tarayıcıdan site+tarama kontrolü, açığın yeri ve çözüm önerisi. Yeni bağımlılık yok
(stdlib http.server). Yalnızca sahibi olunan/yetki verilen hedeflerde çalıştır (§10 etik).

Örnek:
  python -m scripts.serve_ui                          # http://127.0.0.1:8787
  python -m scripts.serve_ui --host 0.0.0.0 --port 9000 --out runs/
"""
from __future__ import annotations

import argparse
import pathlib
import sys

# Kurulum yapılmadan da çalışsın diye src'yi path'e ekle.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from pentestai.webui import ScanManager, ScannerRunner, WebApp, WebServer  # noqa: E402


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="serve_ui", description="Sentinel-Agent Web UI kontrol paneli")
    p.add_argument("--host", default="127.0.0.1", help="bind adresi (varsayılan: 127.0.0.1 — yerel)")
    p.add_argument("--port", type=int, default=8787, help="port (varsayılan: 8787)")
    p.add_argument("--out", default="runs/", help="tarama çıktı klasörü (varsayılan: runs/)")
    p.add_argument("--config-dir", default="config", help="form varsayılanları için config klasörü")
    args = p.parse_args(argv)

    manager = ScanManager(ScannerRunner(out_dir=args.out))
    app = WebApp(manager, runs_dir=args.out, config_dir=args.config_dir)
    server = WebServer(app, host=args.host, port=args.port)
    print(f"[web-ui] http://{args.host}:{args.port}  (çıktı: {args.out})  — durdurmak için Ctrl-C")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[web-ui] durduruldu.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
