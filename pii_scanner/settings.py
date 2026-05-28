"""執行環境設定（Azure App Service B1 等級預設較保守）。"""
from __future__ import annotations

import os


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return int(raw)


# 上傳檔案上限（MB）；B1 建議 5，本機開發可設 PII_MAX_UPLOAD_MB=10
MAX_UPLOAD_BYTES = _int_env("PII_MAX_UPLOAD_MB", 5) * 1024 * 1024

# 整站爬蟲 API 單次最多頁數；B1 建議 ≤10，避免 230s 請求逾時
MAX_SITE_PAGES = _int_env("PII_MAX_SITE_PAGES", 10)
MAX_SITE_DEPTH = _int_env("PII_MAX_SITE_DEPTH", 2)

# 單一 URL / 整站掃描 HTTP timeout（秒）
HTTP_TIMEOUT = float(os.getenv("PII_HTTP_TIMEOUT", "15"))
