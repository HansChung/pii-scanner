"""FastAPI Web UI：提供文字 / URL / 上傳檔案掃描的網頁介面與 REST API。"""
from __future__ import annotations

import asyncio
import secrets
from pathlib import Path
from typing import List, Optional

from fastapi import Body, Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from ..detectors import get_active_detectors
from ..detectors.base import Finding
from ..report import findings_to_dict, render_html
from ..scanners.document_reader import DocumentReadError
from ..scanners.file_scanner import scan_bytes
from ..scanners.text_scanner import scan_text
from ..scanners.web_scanner import scan_site, scan_url
from ..settings import ADMIN_PASSWORD, HTTP_TIMEOUT, MAX_SITE_DEPTH, MAX_SITE_PAGES, MAX_UPLOAD_BYTES
from ..whitelist import WhitelistConfig, apply_whitelist, list_known_detectors, load_whitelist, save_whitelist

app = FastAPI(title="PII Scanner", version="0.2.1", description="自動個資掃描 API")
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
    findings = await asyncio.to_thread(
        scan_text, text, source="api:text", detectors=get_active_detectors()
    )
    return _respond(findings)


@app.post("/api/scan/file")
async def api_scan_file(file: UploadFile = File(...)) -> JSONResponse:
    raw = await file.read()
    if len(raw) > MAX_UPLOAD_BYTES:
        mb = MAX_UPLOAD_BYTES // (1024 * 1024)
        raise HTTPException(status_code=413, detail=f"上傳檔案過大 (>{mb}MB)")

    filename = file.filename or "upload"

    def _run() -> List[Finding]:
        return scan_bytes(raw, filename, detectors=get_active_detectors())

    try:
        findings = await asyncio.to_thread(_run)
    except DocumentReadError as exc:
        raise HTTPException(status_code=415, detail=str(exc))
    return _respond(findings)


@app.post("/api/scan/url")
async def api_scan_url(url: str = Form(...)) -> JSONResponse:
    try:
        findings = await asyncio.to_thread(
            scan_url, url, timeout=HTTP_TIMEOUT, detectors=get_active_detectors()
        )
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
        findings = await asyncio.to_thread(
            scan_site,
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
    findings = await asyncio.to_thread(
        scan_text, text, source="api:text", detectors=get_active_detectors()
    )
    return HTMLResponse(render_html(_finalize(findings)))


@app.get("/admin", response_class=HTMLResponse)
def admin_page(_: str = Depends(_require_admin)) -> HTMLResponse:
    return HTMLResponse(ADMIN_HTML.read_text(encoding="utf-8"))


@app.get("/admin/api/config")
async def admin_get_config(_: str = Depends(_require_admin)) -> JSONResponse:
    def _load() -> dict:
        cfg = load_whitelist()
        return {"config": cfg.to_dict(), "detectors": list_known_detectors()}

    try:
        return JSONResponse(await asyncio.to_thread(_load))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"讀取白名單失敗：{exc}")


@app.put("/admin/api/config")
@app.post("/admin/api/config")
async def admin_put_config(
    payload: dict = Body(...),
    _: str = Depends(_require_admin),
) -> JSONResponse:
    def _save() -> dict:
        cfg = WhitelistConfig.from_dict(payload)
        save_whitelist(cfg)
        return {"ok": True, "config": cfg.to_dict()}

    try:
        return JSONResponse(await asyncio.to_thread(_save))
    except OSError as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    except (TypeError, ValueError, KeyError) as exc:
        raise HTTPException(status_code=400, detail=f"格式錯誤：{exc}")


@app.get("/healthz", response_class=PlainTextResponse)
def healthz() -> str:
    return "ok"
