"""執行環境設定（Azure App Service B1 等級預設較保守）。"""
from __future__ import annotations

import os
from pathlib import Path


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return int(raw)


def _bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


# 上傳檔案上限（MB）；B1 建議 5，本機開發可設 PII_MAX_UPLOAD_MB=10
MAX_UPLOAD_BYTES = _int_env("PII_MAX_UPLOAD_MB", 5) * 1024 * 1024

# 整站爬蟲 API 單次最多頁數；B1 建議 ≤10，避免 230s 請求逾時
MAX_SITE_PAGES = _int_env("PII_MAX_SITE_PAGES", 10)
MAX_SITE_DEPTH = _int_env("PII_MAX_SITE_DEPTH", 2)

# 單一 URL / 整站掃描 HTTP timeout（秒）
HTTP_TIMEOUT = float(os.getenv("PII_HTTP_TIMEOUT", "15"))

# 百家姓全文掃描預設關閉（網站掃描誤判率高）；設 PII_ENABLE_SURNAME_NAME=true 才啟用
ENABLE_SURNAME_NAME = _bool_env("PII_ENABLE_SURNAME_NAME", False)

# 頁尾維護/承辦人等依法公開姓名不列入個資；設 PII_EXCLUDE_PUBLIC_DISCLOSURE=false 可關閉
EXCLUDE_PUBLIC_DISCLOSURE = _bool_env("PII_EXCLUDE_PUBLIC_DISCLOSURE", True)

# Office / 開放文件 / PDF：工作表或 PDF 頁數上限、每工作表最多列數（B1 保守預設）
MAX_DOCUMENT_SHEETS = _int_env("PII_MAX_DOCUMENT_SHEETS", 30)
MAX_DOCUMENT_ROWS = _int_env("PII_MAX_DOCUMENT_ROWS", 5000)

# 管理介面密碼；未設定則 /admin 不可用
ADMIN_PASSWORD = os.getenv("PII_ADMIN_PASSWORD", os.getenv("ADMIN_PASSWORD", "")).strip()

# 白名單 JSON 路徑；Azure 建議 /home/site/whitelist/config.json（重部署不會消失）
_default_whitelist = (
    Path("/home/site/whitelist/config.json")
    if Path("/home/site").exists()
    else Path(__file__).resolve().parent.parent / "data" / "whitelist.json"
)
WHITELIST_PATH = Path(os.getenv("PII_WHITELIST_PATH", str(_default_whitelist)))
