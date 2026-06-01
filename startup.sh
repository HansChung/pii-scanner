#!/bin/bash
# Azure App Service (Linux) startup for the Flask review station.
set -euo pipefail

if [ -d "antenv/bin" ]; then
  # shellcheck disable=SC1091
  source antenv/bin/activate
elif [ -d "/home/site/wwwroot/antenv/bin" ]; then
  # shellcheck disable=SC1091
  source /home/site/wwwroot/antenv/bin/activate
fi

PORT="${PORT:-8000}"
WORKERS="${WEB_CONCURRENCY:-1}"
TIMEOUT="${GUNICORN_TIMEOUT:-180}"

if [ -d "/home/site" ]; then
  mkdir -p /home/site/whitelist /home/site/pii-scanner-instance
  export DATABASE_PATH="${DATABASE_PATH:-/home/site/pii-scanner-instance/app.db}"
  export TEMP_UPLOAD_DIR="${TEMP_UPLOAD_DIR:-/tmp/pii-scanner-uploads}"
else
  mkdir -p instance tmp/uploads
  export DATABASE_PATH="${DATABASE_PATH:-$(pwd)/instance/app.db}"
  export TEMP_UPLOAD_DIR="${TEMP_UPLOAD_DIR:-$(pwd)/tmp/uploads}"
fi

echo "Starting Flask PII review station on port ${PORT} with ${WORKERS} worker(s)..."

exec gunicorn \
  -w "${WORKERS}" \
  --threads "${GUNICORN_THREADS:-8}" \
  "app:create_app()" \
  --bind "0.0.0.0:${PORT}" \
  --timeout "${TIMEOUT}" \
  --graceful-timeout 30 \
  --keep-alive 5 \
  --access-logfile - \
  --error-logfile -
