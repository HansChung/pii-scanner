"""ZIP 壓縮包與 sitemap / 擴充連結來源測試。"""

from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch
from zipfile import ZIP_DEFLATED, ZipFile

import pytest
from openpyxl import Workbook

from pii_scanner.scanners.archive import extract_zip_members, is_zip_archive
from pii_scanner.scanners.file_scanner import scan_bytes
from pii_scanner.scanners.scan_issue import ScanIssue
from pii_scanner.scanners.web_scanner import (
    _extract_links,
    discover_sitemap_urls,
    is_archive_url,
    is_downloadable_url,
    is_textual_url,
    scan_site,
    scan_url,
)

FIXTURES = Path(__file__).parent / "fixtures"


# ---------- ZIP archive ----------

def _make_xlsx_bytes(sheet_name: str = "名單") -> bytes:
    wb = Workbook()
    ws = wb.active
    ws.title = sheet_name
    ws.append(["姓名", "手機"])
    ws.append(["王小明", "0912345678"])
    buf = BytesIO()
    wb.save(buf)
    return buf.getvalue()


def _make_zip_bytes() -> bytes:
    """ZIP containing one .xlsx and one .txt file."""
    buf = BytesIO()
    with ZipFile(buf, "w", ZIP_DEFLATED) as zf:
        zf.writestr("inner/report.xlsx", _make_xlsx_bytes("學生"))
        zf.writestr("contact.txt", "聯絡人 王小明 手機 0987654321")
    return buf.getvalue()


def test_is_zip_archive_distinguishes_office():
    assert is_zip_archive(_make_zip_bytes())
    assert not is_zip_archive(_make_xlsx_bytes())


def test_extract_zip_members_returns_files_not_dirs():
    members = extract_zip_members(_make_zip_bytes())
    names = {m.name for m in members}
    assert "inner/report.xlsx" in names
    assert "contact.txt" in names
    assert all(m.size > 0 for m in members)


def test_scan_bytes_handles_zip_with_nested_xlsx_and_txt():
    issues: list[ScanIssue] = []
    stats: dict = {}
    findings = scan_bytes(_make_zip_bytes(), "bundle.zip", stats=stats, issues=issues)
    detectors = {f.detector for f in findings}
    assert "taiwan_mobile" in detectors
    sources = [f.source for f in findings if f.source]
    # source 應該是 bundle.zip!inner/report.xlsx#學生 或 bundle.zip!contact.txt
    assert any(s.startswith("bundle.zip!inner/report.xlsx#") for s in sources)
    assert any(s.startswith("bundle.zip!contact.txt") for s in sources)
    assert stats.get("archive_total") >= 2


def test_scan_bytes_zip_preview_keys_use_archive_prefix():
    preview: dict[str, str] = {}
    scan_bytes(_make_zip_bytes(), "bundle.zip", preview=preview)
    keys = list(preview.keys())
    assert any(k.startswith("bundle.zip!") for k in keys)


def test_scan_bytes_nested_zip_not_recursed():
    """ZIP 內含 ZIP：第二層的 ZIP 不再展開（防止無限遞迴）。"""
    inner_zip = _make_zip_bytes()
    outer = BytesIO()
    with ZipFile(outer, "w", ZIP_DEFLATED) as zf:
        zf.writestr("nested.zip", inner_zip)
    issues: list[ScanIssue] = []
    findings = scan_bytes(outer.getvalue(), "outer.zip", issues=issues)
    # 內層 ZIP 不會展開（深度限制），所以不會找到 0912345678
    detectors = {f.detector for f in findings}
    assert "taiwan_mobile" not in detectors


# ---------- web scanner: archive URL ----------

def _mock_response(*, content: bytes, content_type: str = "application/octet-stream", status_code: int = 200):
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.content = content
    resp.text = content.decode("utf-8", errors="replace")
    resp.headers = {"Content-Type": content_type}
    resp.status_code = status_code
    return resp


def test_is_archive_url_and_textual():
    assert is_archive_url("https://example.com/files/bundle.zip")
    assert not is_archive_url("https://example.com/page")
    assert is_textual_url("https://example.com/data.csv")
    assert is_downloadable_url("https://example.com/data.json")
    assert is_downloadable_url("https://example.com/report.pdf")


@patch("pii_scanner.scanners.web_scanner.requests.get")
def test_scan_url_zip_response_extracts_and_scans(mock_get):
    mock_get.return_value = _mock_response(content=_make_zip_bytes(), content_type="application/zip")
    findings = scan_url("https://example.com/bundle.zip")
    assert any(f.detector == "taiwan_mobile" for f in findings)
    sources = [f.source for f in findings if f.source]
    assert any(s.startswith("https://example.com/bundle.zip!") for s in sources)


@patch("pii_scanner.scanners.web_scanner.requests.get")
def test_scan_url_csv_response_scanned_as_text(mock_get):
    mock_get.return_value = _mock_response(
        content="姓名,手機\n王小明,0912345678\n".encode("utf-8"),
        content_type="application/octet-stream",  # 故意非 text/csv
    )
    findings = scan_url("https://example.com/data.csv")
    assert any(f.detector == "taiwan_mobile" for f in findings)


# ---------- extended link extraction ----------

def test_extract_links_includes_iframe_embed_object():
    html = """
    <html><body>
      <a href="/page1">page</a>
      <iframe src="/embed.html"></iframe>
      <embed src="/file.pdf" />
      <object data="/data.pdf"></object>
      <source src="/audio.mp3" />
      <link rel="alternate" href="/feed" />
      <a href="javascript:void(0)">no</a>
      <a href="mailto:a@b.com">no</a>
    </body></html>
    """
    urls = _extract_links("https://example.com/", html)
    assert "https://example.com/page1" in urls
    assert "https://example.com/embed.html" in urls
    assert "https://example.com/file.pdf" in urls
    assert "https://example.com/data.pdf" in urls
    assert "https://example.com/audio.mp3" in urls
    assert "https://example.com/feed" in urls
    assert not any("javascript:" in u or "mailto:" in u for u in urls)


# ---------- sitemap discovery ----------

@patch("pii_scanner.scanners.web_scanner.requests.get")
def test_discover_sitemap_urls_simple(mock_get):
    sitemap_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
      <url><loc>https://example.com/a</loc></url>
      <url><loc>https://example.com/b</loc></url>
    </urlset>"""

    def side(url, **kw):
        if url.endswith("/sitemap.xml"):
            return _mock_response(content=sitemap_xml.encode("utf-8"), content_type="application/xml")
        return _mock_response(content=b"", content_type="text/html", status_code=404)

    mock_get.side_effect = side
    urls = discover_sitemap_urls("https://example.com")
    assert "https://example.com/a" in urls
    assert "https://example.com/b" in urls


@patch("pii_scanner.scanners.web_scanner.requests.get")
def test_discover_sitemap_index_follows_children(mock_get):
    index_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
      <sitemap><loc>https://example.com/sitemap-pages.xml</loc></sitemap>
    </sitemapindex>"""
    pages_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
      <url><loc>https://example.com/p1</loc></url>
      <url><loc>https://example.com/p2</loc></url>
    </urlset>"""

    def side(url, **kw):
        if url.endswith("/sitemap.xml"):
            return _mock_response(content=index_xml.encode("utf-8"), content_type="application/xml")
        if url.endswith("/sitemap-pages.xml"):
            return _mock_response(content=pages_xml.encode("utf-8"), content_type="application/xml")
        return _mock_response(content=b"", content_type="text/html", status_code=404)

    mock_get.side_effect = side
    urls = discover_sitemap_urls("https://example.com")
    assert "https://example.com/p1" in urls
    assert "https://example.com/p2" in urls


# ---------- scan_site stats & sitemap integration ----------

@patch("pii_scanner.scanners.web_scanner.time.sleep", return_value=None)
@patch("pii_scanner.scanners.web_scanner._allowed_by_robots", return_value=True)
@patch("pii_scanner.scanners.web_scanner.requests.get")
def test_scan_site_records_breakdown_stats(mock_get, _robots, _sleep):
    html_pages = {
        "https://example.com/": '<html><body><a href="/a.zip">ZIP</a><a href="/b.csv">CSV</a></body></html>',
    }
    csv_bytes = "姓名,Email\n王,a@b.com\n".encode("utf-8")
    zip_bytes = _make_zip_bytes()

    def side(url, **kw):
        r = MagicMock()
        r.raise_for_status = MagicMock()
        r.status_code = 200
        if url in html_pages:
            html = html_pages[url]
            r.content = html.encode("utf-8"); r.text = html
            r.headers = {"Content-Type": "text/html"}
        elif url.endswith(".zip"):
            r.content = zip_bytes; r.text = ""
            r.headers = {"Content-Type": "application/zip"}
        elif url.endswith(".csv"):
            r.content = csv_bytes; r.text = csv_bytes.decode("utf-8")
            r.headers = {"Content-Type": "text/csv"}
        else:
            r.status_code = 404
            r.content = b""; r.text = ""
            r.headers = {"Content-Type": "text/html"}
            r.raise_for_status = MagicMock(side_effect=Exception("404"))
        return r

    mock_get.side_effect = side
    stats: dict = {}
    findings = scan_site(
        "https://example.com/",
        max_pages=10, max_depth=1, delay=0, respect_robots=False, stats=stats,
    )
    assert stats["html_scanned"] >= 1
    assert stats["archives_scanned"] >= 1
    assert stats["text_scanned"] >= 1
    assert any(f.source and f.source.startswith("https://example.com/a.zip!") for f in findings)
