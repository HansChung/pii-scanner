"""網站掃描器：文件下載連結測試。"""

from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from openpyxl import Workbook

from pii_scanner.scanners.web_scanner import (
    _resolve_document_ext,
    is_document_url,
    scan_site,
    scan_url,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _mock_response(*, url: str, content: bytes, content_type: str = "application/octet-stream"):
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.content = content
    resp.text = content.decode("utf-8", errors="replace")
    resp.headers = {"Content-Type": content_type}
    return resp


def _make_xlsx_bytes() -> bytes:
    wb = Workbook()
    ws = wb.active
    ws.title = "名單"
    ws.append(["姓名", "手機"])
    ws.append(["王小明", "0912345678"])
    buf = BytesIO()
    wb.save(buf)
    return buf.getvalue()


def test_is_document_url():
    assert is_document_url("https://example.com/files/report.pdf")
    assert is_document_url("https://example.com/a/b/data.xlsx?token=1")
    assert not is_document_url("https://example.com/about.html")


def test_resolve_document_ext_from_sniff():
    pdf = (FIXTURES / "sample.pdf").read_bytes()
    ext = _resolve_document_ext("https://example.com/download?id=1", "application/octet-stream", pdf)
    assert ext == ".pdf"


def test_resolve_document_ext_from_url():
    ext = _resolve_document_ext(
        "https://example.com/report.pdf",
        "application/octet-stream",
        b"not a real pdf",
    )
    assert ext == ".pdf"


@patch("pii_scanner.scanners.web_scanner.requests.get")
def test_scan_url_pdf(mock_get):
    pdf = (FIXTURES / "sample.pdf").read_bytes()
    mock_get.return_value = _mock_response(
        url="https://example.com/report.pdf",
        content=pdf,
        content_type="application/pdf",
    )
    findings = scan_url("https://example.com/report.pdf")
    assert any(f.detector == "taiwan_mobile" for f in findings)
    assert any("page=1" in (f.source or "") for f in findings)


@patch("pii_scanner.scanners.web_scanner.requests.get")
def test_scan_url_xlsx(mock_get):
    xlsx = _make_xlsx_bytes()
    mock_get.return_value = _mock_response(
        url="https://example.com/list.xlsx",
        content=xlsx,
        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )
    findings = scan_url("https://example.com/list.xlsx")
    assert any(f.detector == "taiwan_mobile" for f in findings)
    assert any("名單" in (f.source or "") for f in findings)


@patch("pii_scanner.scanners.web_scanner.time.sleep", return_value=None)
@patch("pii_scanner.scanners.web_scanner._allowed_by_robots", return_value=True)
@patch("pii_scanner.scanners.web_scanner.requests.get")
def test_scan_site_follows_document_link(mock_get, _robots, _sleep):
    pdf = (FIXTURES / "sample.pdf").read_bytes()
    html = """
    <html><body>
    <a href="/docs/report.pdf">下載報告</a>
    </body></html>
    """

    def side_effect(url, **kwargs):
        if url.endswith(".pdf"):
            return _mock_response(url=url, content=pdf, content_type="application/pdf")
        return _mock_response(url=url, content=html.encode("utf-8"), content_type="text/html")

    mock_get.side_effect = side_effect
    findings = scan_site(
        "https://example.com/",
        max_pages=5,
        max_depth=0,
        delay=0,
        respect_robots=False,
    )
    assert any(f.detector == "taiwan_mobile" for f in findings)
    requested_urls = [call.args[0] for call in mock_get.call_args_list]
    assert "https://example.com/docs/report.pdf" in requested_urls
