#!/bin/bash
# Azure App Service (Linux) startup for the existing FastAPI scanner.
set -euo pipefail

if [ -d "antenv/bin" ]; then
  # shellcheck disable=SC1091
  source antenv/bin/activate
elif [ -d "/home/site/wwwroot/antenv/bin" ]; then
  # shellcheck disable=SC1091
  source /home/site/wwwroot/antenv/bin/activate
fi

mkdir -p /home/site/whitelist 2>/dev/null || true

PORT="${PORT:-8000}"
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
