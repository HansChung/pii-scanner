"""FastAPI Web UI：提供文字 / URL / 上傳檔案掃描的網頁介面與 REST API。

啟動方式::

    uvicorn pii_scanner.web.app:app --reload --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from ..detectors import detect_in_text
from ..report import findings_to_dict, render_html
from ..scanners.text_scanner import scan_text
from ..scanners.web_scanner import scan_site, scan_url

app = FastAPI(title="PII Scanner", version="0.1.0", description="自動個資掃描 API")

INDEX_HTML = Path(__file__).parent / "templates" / "index.html"


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    return HTMLResponse(INDEX_HTML.read_text(encoding="utf-8"))


@app.post("/api/scan/text")
async def api_scan_text(text: str = Form(...)) -> JSONResponse:
    findings = scan_text(text, source="api:text")
    return JSONResponse(findings_to_dict(findings))


@app.post("/api/scan/file")
async def api_scan_file(file: UploadFile = File(...)) -> JSONResponse:
    raw = await file.read()
    if len(raw) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="上傳檔案過大 (>10MB)")
    text: Optional[str] = None
    for enc in ("utf-8", "utf-8-sig", "big5", "cp950", "latin-1"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        raise HTTPException(status_code=415, detail="無法解碼此檔案 (疑似二進位)")
    findings = detect_in_text(text, source=file.filename or "upload")
    return JSONResponse(findings_to_dict(findings))


@app.post("/api/scan/url")
async def api_scan_url(url: str = Form(...)) -> JSONResponse:
    try:
        findings = scan_url(url)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"抓取 URL 失敗：{exc}")
    return JSONResponse(findings_to_dict(findings))


@app.post("/api/scan/site")
async def api_scan_site(
    url: str = Form(...),
    max_pages: int = Form(15),
    max_depth: int = Form(1),
) -> JSONResponse:
    try:
        findings = scan_site(url, max_pages=max_pages, max_depth=max_depth)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"爬取網站失敗：{exc}")
    return JSONResponse(findings_to_dict(findings))


@app.post("/api/scan/text/html", response_class=HTMLResponse)
async def api_scan_text_html(text: str = Form(...)) -> HTMLResponse:
    findings = scan_text(text, source="api:text")
    return HTMLResponse(render_html(findings))


@app.get("/healthz", response_class=PlainTextResponse)
def healthz() -> str:
    return "ok"
