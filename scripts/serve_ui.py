"""Sentinel-Agent Web UI sunucusu (ince katman → WebServer). CLAUDE.md §9.

Tarayıcıdan site+tarama kontrolü, açığın yeri ve çözüm önerisi. Yeni bağımlılık yok
(stdlib http.server). Yalnızca sahibi olunan/yetki verilen hedeflerde çalıştır (§10 etik).

Tarama scope'u İSTEKTEN değil buradaki --scope dosyasından gelir; panel yalnızca onu
DARALTABİLİR (CLAUDE.md §5.6). --scope dosyası yoksa ve yanında bir *.example.yaml varsa panel
onu ilk açılışta kopyalayıp kendi örnek scope'unu üretir (kullanıcı elle `cp` çalıştırmaz);
hiçbiri yoksa panel açılır ama tarama başlatılamaz (503).

Örnek:
  python -m scripts.serve_ui                          # http://127.0.0.1:8787
  python -m scripts.serve_ui --scope config/scope.yaml --secrets-dir .secrets
  python -m scripts.serve_ui --host 0.0.0.0 --port 9000 --allowed-host 192.168.1.5:9000
"""
from __future__ import annotations

import argparse
import pathlib
import sys

# Kurulum yapılmadan da çalışsın diye src'yi path'e ekle.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from pentestai.config import load_scope_config  # noqa: E402
from pentestai.webui import RequestGuard, ScanManager, ScannerRunner, WebApp, WebServer  # noqa: E402

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _bootstrap_example_scope(scope_path: pathlib.Path) -> None:
    """`scope_path` yoksa yanındaki `<ad>.example.yaml`'ı kopyalayıp ilk açılışta panelin
    tarama başlatabilmesini sağlar — kullanıcı elle `cp config/scope.example.yaml ...` çalıştırmaz
    (madde 14, GOREVLER.md). Örnek dosya da yoksa sessizce vazgeçer; çağıran 503 uyarısını basar."""
    if scope_path.exists():   # var olan kullanıcı scope'unu asla ezme
        return
    example_path = scope_path.with_name(scope_path.stem + ".example" + scope_path.suffix)
    if not example_path.exists():
        return
    # example_path scope_path ile aynı klasörde yaşar; o var olduğuna göre klasör de zaten var.
    scope_path.write_text(example_path.read_text(encoding="utf-8"), encoding="utf-8")
    print(f"[web-ui] {scope_path} yoktu — {example_path.name}'tan örnek scope oluşturuldu "
          "(kendi hedefine karşı çalıştırmadan önce hedef/kimlik bilgilerini güncelle).")


def _default_allowed_hosts(bind_host: str, port: int) -> list[str]:
    """Panel loopback'e bağlıysa tarayıcının kullanabileceği TÜM yerel isimler (127.0.0.1/
    localhost/[::1]) otomatik izinlidir — kullanıcı hangisini yazarsa yazsın çalışır."""
    return [f"{h}:{port}" for h in ("127.0.0.1", "localhost", "[::1]")]


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="serve_ui", description="Sentinel-Agent Web UI kontrol paneli")
    p.add_argument("--host", default="127.0.0.1", help="bind adresi (varsayılan: 127.0.0.1 — yerel)")
    p.add_argument("--port", type=int, default=8787, help="port (varsayılan: 8787)")
    p.add_argument("--out", default="runs/", help="tarama çıktı klasörü (varsayılan: runs/)")
    p.add_argument("--config-dir", default="config", help="form varsayılanları için config klasörü")
    p.add_argument("--scope", default="config/scope.yaml",
                   help="tarama scope'u (varsayılan: config/scope.yaml; yoksa panel açılır ama "
                        "tarama başlatılamaz)")
    p.add_argument("--secrets-dir", default=".secrets",
                   help="storagestate_path'in içinden gösterebileceği klasör (varsayılan: .secrets)")
    p.add_argument("--allowed-host", action="append", default=[],
                   help="ek izinli Host başlığı (host:port) — --host loopback dışına "
                        "(ör. 0.0.0.0) bağlanırken ZORUNLU; birden çok kez verilebilir")
    args = p.parse_args(argv)

    if args.host not in _LOOPBACK_HOSTS and not args.allowed_host:
        print(f"[web-ui] HATA: --host {args.host} loopback değil (ağa açık) — bu durumda en az bir "
              "--allowed-host (host:port) vermelisin, aksi halde hiçbir istek Host kontrolünü "
              "geçemez ve panel kimseye açılamaz. Örnek: --allowed-host 192.168.1.5:8787")
        return 2

    allowed_hosts = list(_default_allowed_hosts(args.host, args.port)) + list(args.allowed_host)
    guard = RequestGuard(allowed_hosts)

    scope_path = pathlib.Path(args.scope)
    if not scope_path.exists():
        _bootstrap_example_scope(scope_path)

    server_scope = server_budget = None
    if scope_path.exists():
        _, server_scope, server_budget = load_scope_config(str(scope_path))
        print(f"[web-ui] scope kilitlendi: {scope_path} (istek yalnızca daraltabilir)")
    else:
        print(f"[web-ui] UYARI: {scope_path} yok — panel açılır ama tarama BAŞLATILAMAZ "
              f"({scope_path.with_name(scope_path.stem + '.example' + scope_path.suffix)} de yok)")

    manager = ScanManager(ScannerRunner(out_dir=args.out))
    app = WebApp(
        manager, runs_dir=args.out, config_dir=args.config_dir, guard=guard,
        server_scope=server_scope, server_budget=server_budget, secrets_dir=args.secrets_dir,
    )
    server = WebServer(app, host=args.host, port=args.port)
    print(f"[web-ui] http://{args.host}:{args.port}  (çıktı: {args.out})  — durdurmak için Ctrl-C")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[web-ui] durduruldu.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
