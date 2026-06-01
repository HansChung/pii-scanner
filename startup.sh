#!/usr/bin/env bash
set -euo pipefail

exec gunicorn "app:create_app()" --bind="0.0.0.0:${PORT:-8000}" --workers=1 --threads=8 --timeout=180
