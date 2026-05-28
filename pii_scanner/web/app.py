"""FastAPI Web UI：提供文字 / URL / 上傳檔案掃描的網頁介面與 REST API。

啟動方式::

    uvicorn pii_scanner.web.app:app --reload --host 0.0.0.0 --port 8000

Azure App Service (B1)::

    bash startup.sh

管理介面：設定環境變數 ``PII_ADMIN_PASSWORD`` 後開啟 ``/admin``。
"""
from __future__ import annotations

import secrets
from pathlib import Path
from typing import List, Optional

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from ..detectors import detect_in_text, get_active_detectors
from ..detectors.base import Finding
from ..report import findings_to_dict, render_html
from ..scanners.text_scanner import scan_text
from ..scanners.web_scanner import scan_site, scan_url
from ..settings import ADMIN_PASSWORD, HTTP_TIMEOUT, MAX_SITE_DEPTH, MAX_SITE_PAGES, MAX_UPLOAD_BYTES
from ..whitelist import WhitelistConfig, apply_whitelist, list_known_detectors, load_whitelist, save_whitelist

app = FastAPI(title="PII Scanner", version="0.2.0", description="自動個資掃描 API")
security = HTTPBasic(auto_error=False)

TEMPLATES = Path(__file__).parent / "templates"
INDEX_HTML = TEMPLATES / "index.html"
ADMIN_HTML = TEMPLATES / "admin.html"


def _finalize(findings: List[Finding]) -> List[Finding]:
    return apply_whitelist(findings)


def _respond(findings: List[Finding]) -> JSONResponse:
    return JSONResponse(findings_to_dict(_finalize(findings)))


def _require_admin(credentials: Optional[HTTPBasicCredentials] = Depends(security)) -> str:
    if not ADMIN_PASSWORD:
        raise HTTPException(
            status_code=503,
            detail="管理介面未啟用。請在 Azure 應用程式設定加入 PII_ADMIN_PASSWORD。",
        )
    if credentials is None:
        raise HTTPException(status_code=401, detail="需要管理員登入", headers={"WWW-Authenticate": "Basic"})
    ok_user = secrets.compare_digest(credentials.username.encode(), b"admin")
    ok_pass = secrets.compare_digest(credentials.password.encode(), ADMIN_PASSWORD.encode())
    if not (ok_user and ok_pass):
        raise HTTPException(status_code=401, detail="帳號或密碼錯誤", headers={"WWW-Authenticate": "Basic"})
    return credentials.username


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    return HTMLResponse(INDEX_HTML.read_text(encoding="utf-8"))


@app.post("/api/scan/text")
async def api_scan_text(text: str = Form(...)) -> JSONResponse:
    findings = scan_text(text, source="api:text", detectors=get_active_detectors())
    return _respond(findings)


@app.post("/api/scan/file")
async def api_scan_file(file: UploadFile = File(...)) -> JSONResponse:
    raw = await file.read()
    if len(raw) > MAX_UPLOAD_BYTES:
        mb = MAX_UPLOAD_BYTES // (1024 * 1024)
        raise HTTPException(status_code=413, detail=f"上傳檔案過大 (>{mb}MB)")
    text: Optional[str] = None
    for enc in ("utf-8", "utf-8-sig", "big5", "cp950", "latin-1"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        raise HTTPException(status_code=415, detail="無法解碼此檔案 (疑似二進位)")
    findings = detect_in_text(text, source=file.filename or "upload", detectors=get_active_detectors())
    return _respond(findings)


@app.post("/api/scan/url")
async def api_scan_url(url: str = Form(...)) -> JSONResponse:
    try:
        findings = scan_url(url, timeout=HTTP_TIMEOUT, detectors=get_active_detectors())
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"抓取 URL 失敗：{exc}")
    return _respond(findings)


@app.post("/api/scan/site")
async def api_scan_site(
    url: str = Form(...),
    max_pages: int = Form(10),
    max_depth: int = Form(1),
) -> JSONResponse:
    pages = min(max(1, max_pages), MAX_SITE_PAGES)
    depth = min(max(0, max_depth), MAX_SITE_DEPTH)
    try:
        findings = scan_site(
            url,
            max_pages=pages,
            max_depth=depth,
            timeout=HTTP_TIMEOUT,
            detectors=get_active_detectors(),
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"爬取網站失敗：{exc}")
    return _respond(findings)


@app.post("/api/scan/text/html", response_class=HTMLResponse)
async def api_scan_text_html(text: str = Form(...)) -> HTMLResponse:
    findings = scan_text(text, source="api:text", detectors=get_active_detectors())
    return HTMLResponse(render_html(_finalize(findings)))


@app.get("/admin", response_class=HTMLResponse)
def admin_page(_: str = Depends(_require_admin)) -> HTMLResponse:
    return HTMLResponse(ADMIN_HTML.read_text(encoding="utf-8"))


@app.get("/admin/api/config")
def admin_get_config(_: str = Depends(_require_admin)) -> JSONResponse:
    cfg = load_whitelist()
    return JSONResponse({"config": cfg.to_dict(), "detectors": list_known_detectors()})


@app.put("/admin/api/config")
async def admin_put_config(payload: dict, _: str = Depends(_require_admin)) -> JSONResponse:
    try:
        cfg = WhitelistConfig.from_dict(payload)
    except (TypeError, ValueError, KeyError) as exc:
        raise HTTPException(status_code=400, detail=f"格式錯誤：{exc}")
    if not cfg.global_disabled_detectors and "surname_name" not in [
        d for r in cfg.domain_rules for d in r.disabled_detectors
    ]:
        pass  # 允許管理員自行決定
    save_whitelist(cfg)
    return JSONResponse({"ok": True, "config": cfg.to_dict()})


@app.get("/healthz", response_class=PlainTextResponse)
def healthz() -> str:
    return "ok"
