"""原文高亮預覽 + OCR fallback 測試。"""

from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from openpyxl import Workbook

from pii_scanner.detectors.base import Finding, Severity
from pii_scanner.report.renderer import _prepare_preview, findings_to_dict
from pii_scanner.scanners import document_reader
from pii_scanner.scanners.file_scanner import scan_bytes
from pii_scanner.scanners.text_scanner import scan_text

FIXTURES = Path(__file__).parent / "fixtures"


# ---------- Highlight preview ----------

def test_scan_text_fills_preview_dict():
    preview: dict[str, str] = {}
    findings = scan_text(
        "客戶 王小明 手機 0912345678",
        source="api:text",
        preview=preview,
    )
    assert preview.get("api:text", "").startswith("客戶")
    assert any(f.detector == "taiwan_mobile" for f in findings)


def _make_xlsx_bytes() -> bytes:
    wb = Workbook()
    ws = wb.active
    ws.title = "名單"
    ws.append(["姓名", "手機"])
    ws.append(["王小明", "0912345678"])
    buf = BytesIO()
    wb.save(buf)
    return buf.getvalue()


def test_scan_bytes_collects_preview_per_segment():
    preview: dict[str, str] = {}
    findings = scan_bytes(_make_xlsx_bytes(), "sample.xlsx", preview=preview)
    assert any("名單" in s for s in preview.keys())
    assert any(f.detector == "taiwan_mobile" for f in findings)
    # 每段原文應包含我們塞入的手機號（spreadsheet_text 會補關鍵字）
    assert "0912345678" in next(iter(preview.values()))


def test_prepare_preview_only_keeps_sources_with_findings():
    findings = [
        Finding(
            detector="taiwan_mobile", category="phone", severity=Severity.HIGH,
            value="0912345678", masked="0*******78", start=0, end=10,
            source="a.xlsx#Sheet1",
        )
    ]
    preview = {
        "a.xlsx#Sheet1": "0912345678",
        "a.xlsx#Sheet2": "no pii here",
    }
    out = _prepare_preview(preview, findings)
    sources = {item["source"] for item in out}
    assert sources == {"a.xlsx#Sheet1"}


def test_findings_to_dict_includes_preview():
    findings = [
        Finding(
            detector="taiwan_mobile", category="phone", severity=Severity.HIGH,
            value="0912345678", masked="0*******78", start=3, end=13,
            source="api:text",
        )
    ]
    out = findings_to_dict(findings, preview={"api:text": "手機 0912345678 已記錄"})
    assert "preview" in out
    assert out["preview"][0]["source"] == "api:text"
    assert "0912345678" in out["preview"][0]["text"]


# ---------- OCR fallback ----------

def test_image_pdf_without_ocr_raises_with_helpful_msg(monkeypatch):
    """模擬 pypdf 解出空文字，且 OCR 未設定時應拋出友善訊息。"""
    fake_page = MagicMock()
    fake_page.extract_text.return_value = ""
    fake_reader = MagicMock()
    fake_reader.pages = [fake_page]
    fake_reader.is_encrypted = False

    monkeypatch.setattr("pypdf.PdfReader", lambda *a, **kw: fake_reader)
    monkeypatch.setattr("pii_scanner.ocr.is_configured", lambda: False)
    stats: dict = {}
    with pytest.raises(document_reader.DocumentReadError, match="OCR"):
        document_reader.extract_document_segments(b"dummy pdf bytes", "scan.pdf", ext=".pdf", stats=stats)
    assert "ocr_warning" in stats


def test_image_pdf_uses_ocr_when_configured(monkeypatch):
    """模擬 pypdf 解空、Azure DI 可用 → 回傳 OCR 文字片段。"""
    fake_page = MagicMock()
    fake_page.extract_text.return_value = ""
    fake_reader = MagicMock()
    fake_reader.pages = [fake_page, fake_page]
    fake_reader.is_encrypted = False
    monkeypatch.setattr("pypdf.PdfReader", lambda *a, **kw: fake_reader)

    monkeypatch.setattr("pii_scanner.ocr.is_configured", lambda: True)
    monkeypatch.setattr(
        "pii_scanner.ocr.ocr_pdf_pages",
        lambda data, max_pages=30: {1: "OCR 第一頁 手機 0912345678", 2: "OCR 第二頁 Email a@b.com"},
    )

    stats: dict = {}
    segments = document_reader.extract_document_segments(b"dummy pdf", "scan.pdf", ext=".pdf", stats=stats)
    assert stats.get("ocr_used") is True
    assert stats.get("ocr_pages") == 2
    sources = {s.source for s in segments}
    assert "scan.pdf#page=1" in sources
    assert "scan.pdf#page=2" in sources


def test_scan_bytes_propagates_ocr_stats(monkeypatch):
    """經由 scan_bytes 也能拿到 OCR meta。"""
    fake_page = MagicMock()
    fake_page.extract_text.return_value = ""
    fake_reader = MagicMock()
    fake_reader.pages = [fake_page]
    fake_reader.is_encrypted = False
    monkeypatch.setattr("pypdf.PdfReader", lambda *a, **kw: fake_reader)
    monkeypatch.setattr("pii_scanner.ocr.is_configured", lambda: True)
    monkeypatch.setattr(
        "pii_scanner.ocr.ocr_pdf_pages",
        lambda data, max_pages=30: {1: "客戶 王小明 手機 0912345678"},
    )

    stats: dict = {}
    findings = scan_bytes(b"%PDF-1.0\nfake", "scan.pdf", stats=stats)
    assert stats.get("ocr_used") is True
    assert any(f.detector == "taiwan_mobile" for f in findings)
