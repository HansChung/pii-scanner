#!/bin/bash
# Azure App Service (Linux) 啟動腳本 — 針對 B1 (1 vCPU / 1.75GB RAM) 優化
set -euo pipefail

# Oryx 部署後的 Python 虛擬環境（Azure 標準路徑）
if [ -d "antenv/bin" ]; then
  # shellcheck disable=SC1091
  source antenv/bin/activate
elif [ -d "/home/site/wwwroot/antenv/bin" ]; then
  # shellcheck disable=SC1091
  source /home/site/wwwroot/antenv/bin/activate
fi

# 白名單持久化目錄（/home 在 Azure 重部署後仍保留）
mkdir -p /home/site/whitelist 2>/dev/null || true

PORT="${PORT:-8000}"
# B1 記憶體有限，固定 1 worker；若升級至 S1+ 可設 WEB_CONCURRENCY=2
WORKERS="${WEB_CONCURRENCY:-1}"
TIMEOUT="${GUNICORN_TIMEOUT:-120}"

echo "Starting PII Scanner on port ${PORT} with ${WORKERS} worker(s)..."

exec gunicorn \
  -w "${WORKERS}" \
  -k uvicorn.workers.UvicornWorker \
  pii_scanner.web.app:app \
  --bind "0.0.0.0:${PORT}" \
  --timeout "${TIMEOUT}" \
  --graceful-timeout 30 \
  --keep-alive 5 \
  --access-logfile - \
  --error-logfile -
