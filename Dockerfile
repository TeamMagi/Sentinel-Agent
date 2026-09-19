# Sentinel-Agent — reproducible dev/CI imajı (takım için aynı ortam)
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Bağımlılıkları önce kopyala (layer cache)
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Playwright Chromium + sistem bağımlılıkları (auth/login akışı için — DESIGN.md §10.1)
RUN playwright install --with-deps chromium

# Uygulama kodu (compose'ta bind-mount ile override edilir; imaj tek başına da çalışır)
COPY . .

# Varsayılan: geliştirme kabuğu. run_scan CLI: python -m scripts.run_scan --help
CMD ["bash"]
