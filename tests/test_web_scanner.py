"""網站掃描器：文件下載連結與來源 URL 測試。"""

from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

from openpyxl import Workbook

from pii_scanner.scanners.scan_issue import ScanIssue
from pii_scanner.scanners.web_scanner import (
    _resolve_document_ext,
    is_document_url,
    scan_site,
    scan_url,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _mock_response(*, content: bytes, content_type: str = "application/octet-stream"):
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
    assert not is_document_url("https://example.com/about.html")


def test_resolve_document_ext_from_sniff():
    pdf = (FIXTURES / "sample.pdf").read_bytes()
    ext = _resolve_document_ext("https://example.com/download?id=1", "application/octet-stream", pdf)
    assert ext == ".pdf"


@patch("pii_scanner.scanners.web_scanner.requests.get")
def test_scan_url_pdf_uses_full_url_as_source(mock_get):
    pdf = (FIXTURES / "sample.pdf").read_bytes()
    url = "https://example.com/report.pdf"
    mock_get.return_value = _mock_response(content=pdf, content_type="application/pdf")
    findings = scan_url(url)
    assert any(f.detector == "taiwan_mobile" for f in findings)
    assert all(f.source and f.source.startswith(url) for f in findings)
    assert any("#page=1" in (f.source or "") for f in findings)


@patch("pii_scanner.scanners.web_scanner.requests.get")
def test_scan_url_xlsx_per_sheet_source(mock_get):
    xlsx = _make_xlsx_bytes()
    url = "https://example.com/list.xlsx"
    mock_get.return_value = _mock_response(
        content=xlsx,
        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )
    findings = scan_url(url)
    assert any(f.detector == "taiwan_mobile" for f in findings)
    assert any(f.source == f"{url}#名單" for f in findings)


@patch("pii_scanner.scanners.web_scanner.time.sleep", return_value=None)
@patch("pii_scanner.scanners.web_scanner._allowed_by_robots", return_value=True)
@patch("pii_scanner.scanners.web_scanner.requests.get")
def test_scan_site_follows_document_link(mock_get, _robots, _sleep):
    pdf = (FIXTURES / "sample.pdf").read_bytes()
    html = '<html><body><a href="/docs/report.pdf">下載</a></body></html>'
    doc_url = "https://example.com/docs/report.pdf"

    def side_effect(url, **kwargs):
        if url.endswith(".pdf"):
            return _mock_response(content=pdf, content_type="application/pdf")
        return _mock_response(content=html.encode("utf-8"), content_type="text/html")

    mock_get.side_effect = side_effect
    findings = scan_site(
        "https://example.com/",
        max_pages=5,
        max_depth=0,
        delay=0,
        respect_robots=False,
    )
    assert any(f.source and f.source.startswith(doc_url) for f in findings)


@patch("pii_scanner.scanners.web_scanner.time.sleep", return_value=None)
@patch("pii_scanner.scanners.web_scanner._allowed_by_robots", return_value=True)
@patch("pii_scanner.scanners.web_scanner.requests.get")
def test_scan_site_exclude_pattern_skips_url(mock_get, _robots, _sleep):
    pages = {
        "https://example.com/": '<a href="/news/a">news</a><a href="/login">login</a>',
        "https://example.com/news/a": "姓名：王小明 手機 0912345678",
        "https://example.com/login": "姓名：登入頁 機密 A123456789",
    }

    def side_effect(url, **kwargs):
        body = pages.get(url.split("#")[0], "")
        return _mock_response(content=body.encode("utf-8"), content_type="text/html")

    mock_get.side_effect = side_effect
    visited_stats: dict = {}
    scan_site(
        "https://example.com/",
        max_pages=10,
        max_depth=1,
        delay=0,
        respect_robots=False,
        exclude_patterns=["/login"],
        stats=visited_stats,
    )
    fetched = [call.args[0] for call in mock_get.call_args_list]
    assert "https://example.com/news/a" in fetched
    assert "https://example.com/login" not in fetched


@patch("pii_scanner.scanners.web_scanner.time.sleep", return_value=None)
@patch("pii_scanner.scanners.web_scanner._allowed_by_robots", return_value=True)
@patch("pii_scanner.scanners.web_scanner.requests.get")
def test_scan_site_include_pattern_limits_scope(mock_get, _robots, _sleep):
    pages = {
        "https://example.com/": '<a href="/news/a">news</a><a href="/about">about</a>',
        "https://example.com/news/a": "內容",
        "https://example.com/about": "內容",
    }

    def side_effect(url, **kwargs):
        body = pages.get(url.split("#")[0], "")
        return _mock_response(content=body.encode("utf-8"), content_type="text/html")

    mock_get.side_effect = side_effect
    scan_site(
        "https://example.com/",
        max_pages=10,
        max_depth=1,
        delay=0,
        respect_robots=False,
        include_patterns=["/news/"],
    )
    fetched = [call.args[0] for call in mock_get.call_args_list]
    assert "https://example.com/news/a" in fetched
    assert "https://example.com/about" not in fetched


@patch("pii_scanner.scanners.web_scanner.requests.get")
def test_scan_url_document_parse_issue(mock_get):
    url = "https://example.com/bad.xlsx"
    mock_get.return_value = _mock_response(content=b"not excel", content_type="application/octet-stream")
    issues: list[ScanIssue] = []
    findings = scan_url(url, issues=issues)
    assert findings == []
    assert len(issues) == 1
    assert issues[0].path == url
