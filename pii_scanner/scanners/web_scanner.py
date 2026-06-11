"""網站掃描器：抓取 URL，剝去 HTML 後跑 PII 偵測。

預設遵守同一網域、深度限制與 robots.txt。若 URL 或頁面中的下載連結指向
PDF、Word、Excel 等支援格式，會以與檔案上傳相同方式解析（逐頁 / 逐工作表），
命中結果的 source 會保留完整 URL 以便依頁面/檔案彙總。
"""
from __future__ import annotations

import logging
import re
import time
from collections import deque
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Set
from urllib.parse import unquote, urljoin, urlparse
from urllib.robotparser import RobotFileParser

from ..detectors import detect_in_text
from ..detectors.base import BaseDetector, Finding
from .archive import is_zip_archive
from .document_reader import DOCUMENT_SUFFIXES, DocumentReadError, extract_document_segments
from .file_scanner import MAX_FILE_BYTES, scan_bytes
from .format_sniff import sniff_document_suffix
from .scan_issue import ScanIssue

log = logging.getLogger(__name__)

try:
    import requests  # type: ignore
    from bs4 import BeautifulSoup  # type: ignore
except ImportError as exc:  # pragma: no cover - 由 requirements.txt 確保安裝
    requests = None  # type: ignore
    BeautifulSoup = None  # type: ignore
    _IMPORT_ERROR: Optional[ImportError] = exc
else:
    _IMPORT_ERROR = None


DEFAULT_HEADERS = {
    "User-Agent": "pii-scanner/0.1 (+https://example.com/pii-scanner)",
    "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
}

DOCUMENT_CONTENT_TYPES = {
    "application/pdf": ".pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "application/vnd.ms-excel": ".xls",
    "application/vnd.oasis.opendocument.text": ".odt",
    "application/vnd.oasis.opendocument.spreadsheet": ".ods",
}

ARCHIVE_SUFFIXES = {".zip"}
ARCHIVE_CONTENT_TYPES = {
    "application/zip",
    "application/x-zip-compressed",
    "application/x-zip",
}

# 直接以「文字內容」掃描的下載類型（CSV/JSON/純文字等）
TEXT_URL_SUFFIXES = {".csv", ".tsv", ".json", ".jsonl", ".txt", ".log", ".md", ".xml"}


def _check_runtime() -> None:
    if _IMPORT_ERROR is not None:
        raise RuntimeError(
            "缺少 requests / beautifulsoup4 套件，請先執行 "
            "`pip install -r requirements.txt`。"
        ) from _IMPORT_ERROR


def _html_to_text(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    text = soup.get_text(separator="\n")
    text = re.sub(r"\n{2,}", "\n", text)
    return text


def _allowed_by_robots(url: str, user_agent: str, cache: dict) -> bool:
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    rp = cache.get(base)
    if rp is None:
        rp = RobotFileParser()
        rp.set_url(urljoin(base, "/robots.txt"))
        try:
            rp.read()
        except Exception:  # noqa: BLE001
            rp = None
        cache[base] = rp
    if rp is None:
        return True
    return rp.can_fetch(user_agent, url)


def _suffix_from_url_path(url: str) -> Optional[str]:
    path = unquote(urlparse(url).path)
    ext = Path(path).suffix.lower()
    if ext in DOCUMENT_SUFFIXES:
        return ext
    return None


def is_document_url(url: str) -> bool:
    """URL 路徑是否為支援的二進位文件副檔名。"""
    return _suffix_from_url_path(url) is not None


def _url_suffix(url: str) -> str:
    return Path(unquote(urlparse(url).path)).suffix.lower()


def is_archive_url(url: str) -> bool:
    """URL 是否為支援的壓縮包副檔名（目前 .zip）。"""
    return _url_suffix(url) in ARCHIVE_SUFFIXES


def is_textual_url(url: str) -> bool:
    """URL 是否為純文字下載類型（CSV/JSON/TXT…）。"""
    return _url_suffix(url) in TEXT_URL_SUFFIXES


def is_downloadable_url(url: str) -> bool:
    """整站爬取時，是否值得在達到 max_depth 之後仍跟進。"""
    return is_document_url(url) or is_archive_url(url) or is_textual_url(url)


def _filename_from_url(url: str, doc_ext: Optional[str] = None) -> str:
    path = unquote(urlparse(url).path)
    name = Path(path).name or "download"
    if doc_ext and not name.lower().endswith(doc_ext):
        name = f"{Path(name).stem}{doc_ext}"
    return name


def _resolve_document_ext(url: str, content_type: str, data: bytes) -> Optional[str]:
    sniffed = sniff_document_suffix(data[:65536])
    if sniffed:
        return sniffed
    suffix = _suffix_from_url_path(url)
    if suffix:
        return suffix
    ct = content_type.split(";", 1)[0].strip().lower()
    return DOCUMENT_CONTENT_TYPES.get(ct)


def _is_archive_response(url: str, content_type: str, data: bytes) -> bool:
    if is_zip_archive(data[:65536]):
        return True
    ct = content_type.split(";", 1)[0].strip().lower()
    if ct in ARCHIVE_CONTENT_TYPES:
        return True
    return is_archive_url(url)


def _filename_from_url_simple(url: str, default_ext: str = "") -> str:
    path = unquote(urlparse(url).path)
    name = Path(path).name or "download"
    if default_ext and Path(name).suffix.lower() != default_ext:
        name = f"{Path(name).stem or 'download'}{default_ext}"
    return name


def _rewrite_document_sources(findings: List[Finding], url: str) -> None:
    """將 scan_bytes 的檔名 source 改為完整 URL（含 #page / #工作表）。"""
    for f in findings:
        if not f.source:
            f.source = url
            continue
        if "#" in f.source:
            loc = f.source.split("#", 1)[1]
            f.source = f"{url}#{loc}"
        else:
            f.source = url


def _rewrite_preview_sources(preview: dict, url: str) -> None:
    """同樣把 preview 的 key 改為完整 URL。"""
    if not preview:
        return
    new_items = []
    for src, text in list(preview.items()):
        if "#" in src:
            loc = src.split("#", 1)[1]
            new_items.append((f"{url}#{loc}", text))
        else:
            new_items.append((url, text))
        del preview[src]
    for k, v in new_items:
        preview[k] = v


def _document_segments_to_text(data: bytes, url: str, doc_ext: str) -> str:
    filename = _filename_from_url(url, doc_ext)
    if len(data) > MAX_FILE_BYTES:
        data = data[:MAX_FILE_BYTES]
    segments = extract_document_segments(data, filename, ext=doc_ext)
    parts = [seg.text for seg in segments if seg.text.strip()]
    return "\n\n".join(parts)


def _rewrite_archive_prefix(text: str, filename: str, url: str) -> str:
    """``filename`` 或 ``filename!...`` 字首替換為 ``url``。"""
    if text == filename:
        return url
    if text.startswith(filename + "!") or text.startswith(filename + "#"):
        return url + text[len(filename):]
    return text


def _scan_response_as_archive(
    data: bytes,
    url: str,
    *,
    detectors: Optional[Iterable[BaseDetector]] = None,
    issues: Optional[List[ScanIssue]] = None,
    preview: Optional[dict] = None,
    stats: Optional[dict] = None,
) -> List[Finding]:
    """壓縮包下載：交給 scan_bytes 遞迴掃描成員，並把 source 字首改為 URL。"""
    if len(data) > MAX_FILE_BYTES:
        log.warning("壓縮包 %s 超過 %s bytes，已截斷", url, MAX_FILE_BYTES)
        if issues is not None:
            issues.append(
                ScanIssue(url, f"壓縮包超過 {MAX_FILE_BYTES // (1024 * 1024)} MB，已截斷後掃描")
            )
        data = data[:MAX_FILE_BYTES]
    filename = _filename_from_url_simple(url, ".zip")
    sub_preview: Optional[dict] = {} if preview is not None else None
    sub_issues: List[ScanIssue] = []
    try:
        findings = scan_bytes(
            data, filename,
            detectors=detectors,
            preview=sub_preview,
            stats=stats,
            issues=sub_issues,
        )
    except DocumentReadError as exc:
        msg = f"無法解析壓縮包：{exc}"
        log.warning("%s — %s", url, msg)
        if issues is not None:
            issues.append(ScanIssue(url, msg))
        return []

    for f in findings:
        if f.source:
            f.source = _rewrite_archive_prefix(f.source, filename, url)

    if sub_preview is not None and preview is not None:
        for k, v in sub_preview.items():
            preview[_rewrite_archive_prefix(k, filename, url)] = v

    if issues is not None:
        for i in sub_issues:
            issues.append(ScanIssue(_rewrite_archive_prefix(i.path, filename, url), i.reason))

    return findings


def _scan_response_as_document(
    data: bytes,
    url: str,
    doc_ext: str,
    *,
    detectors: Optional[Iterable[BaseDetector]] = None,
    issues: Optional[List[ScanIssue]] = None,
    preview: Optional[dict] = None,
    stats: Optional[dict] = None,
) -> List[Finding]:
    truncated = len(data) > MAX_FILE_BYTES
    if truncated:
        log.warning("文件 %s 超過 %s bytes，已截斷掃描", url, MAX_FILE_BYTES)
        if issues is not None:
            issues.append(
                ScanIssue(url, f"文件超過 {MAX_FILE_BYTES // (1024 * 1024)} MB，已截斷後掃描")
            )
        data = data[:MAX_FILE_BYTES]
    filename = _filename_from_url(url, doc_ext)
    sub_preview: Optional[dict] = {} if preview is not None else None
    try:
        findings = scan_bytes(
            data,
            filename,
            detectors=detectors,
            preview=sub_preview,
            stats=stats,
        )
        _rewrite_document_sources(findings, url)
        if sub_preview is not None and preview is not None:
            _rewrite_preview_sources(sub_preview, url)
            preview.update(sub_preview)
        return findings
    except DocumentReadError as exc:
        msg = f"無法解析下載文件：{exc}"
        log.warning("%s — %s", url, msg)
        if issues is not None:
            issues.append(ScanIssue(url, msg))
        return []


def fetch_url_text(
    url: str,
    *,
    timeout: float = 10.0,
    headers: Optional[dict] = None,
    verify_tls: bool = True,
    url_validator: Optional[Callable[[str], None]] = None,
) -> str:
    """抓取 URL 並回傳純文字（供 AI 增強；含 PDF/Word 等文件文字擷取）。"""
    _check_runtime()
    h = dict(DEFAULT_HEADERS)
    if headers:
        h.update(headers)
    resp = _request_get(
        url, headers=h, timeout=timeout, verify_tls=verify_tls, url_validator=url_validator
    )
    resp.raise_for_status()
    content_type = resp.headers.get("Content-Type", "")
    data = resp.content
    doc_ext = _resolve_document_ext(url, content_type, data)
    if doc_ext:
        try:
            return _document_segments_to_text(data, url, doc_ext)
        except DocumentReadError:
            return ""
    if "html" in content_type or "xml" in content_type:
        return _html_to_text(resp.text)
    return resp.text


def scan_url(
    url: str,
    *,
    detectors: Optional[Iterable[BaseDetector]] = None,
    timeout: float = 10.0,
    headers: Optional[dict] = None,
    verify_tls: bool = True,
    issues: Optional[List[ScanIssue]] = None,
    preview: Optional[dict] = None,
    stats: Optional[dict] = None,
    url_validator: Optional[Callable[[str], None]] = None,
) -> List[Finding]:
    """抓取單一 URL 並掃描（HTML / PDF / Word / Excel / ZIP / CSV / JSON 等）。"""
    _check_runtime()
    h = dict(DEFAULT_HEADERS)
    if headers:
        h.update(headers)
    try:
        resp = _request_get(
            url, headers=h, timeout=timeout, verify_tls=verify_tls, url_validator=url_validator
        )
        resp.raise_for_status()
    except Exception as exc:  # noqa: BLE001
        if issues is not None:
            issues.append(ScanIssue(url, f"抓取失敗：{exc}"))
        raise
    content_type = resp.headers.get("Content-Type", "")
    data = resp.content
    doc_ext = _resolve_document_ext(url, content_type, data)
    if doc_ext:
        return _scan_response_as_document(
            data, url, doc_ext,
            detectors=detectors, issues=issues, preview=preview, stats=stats,
        )
    if _is_archive_response(url, content_type, data):
        return _scan_response_as_archive(
            data, url,
            detectors=detectors, issues=issues, preview=preview, stats=stats,
        )
    if "html" in content_type or "xml" in content_type:
        text = _html_to_text(resp.text)
    elif "text" in content_type or "json" in content_type or is_textual_url(url):
        text = resp.text
    else:
        text = resp.text
    if preview is not None and text:
        preview[url] = text
    return detect_in_text(text, detectors=detectors, source=url)


_LINK_SELECTORS = (
    ("a", "href"),
    ("area", "href"),
    ("iframe", "src"),
    ("embed", "src"),
    ("object", "data"),
    ("source", "src"),
    ("link", "href"),
)
_LINK_REL_ALLOWED = {"alternate", "canonical", "next", "prev"}


def _extract_links(base_url: str, html: str) -> List[str]:
    """從 HTML 抽出可掃描的下游 URL（含 iframe/embed/object/source/link）。"""
    soup = BeautifulSoup(html, "html.parser")
    out: List[str] = []
    seen: Set[str] = set()
    for tag, attr in _LINK_SELECTORS:
        for el in soup.find_all(tag, attrs={attr: True}):
            href = (el.get(attr) or "").strip()
            if not href:
                continue
            low = href.lower()
            if low.startswith(("javascript:", "mailto:", "tel:", "data:", "ftp:")):
                continue
            if tag == "link":
                rels = el.get("rel") or []
                if not any(r in _LINK_REL_ALLOWED for r in rels):
                    continue
            try:
                u = urljoin(base_url, href).split("#", 1)[0]
            except Exception:
                continue
            if not (u.startswith("http://") or u.startswith("https://")):
                continue
            if u in seen:
                continue
            seen.add(u)
            out.append(u)
    return out


def discover_sitemap_urls(
    base_url: str,
    *,
    timeout: float = 10.0,
    headers: Optional[dict] = None,
    verify_tls: bool = True,
    max_urls: int = 500,
    max_sitemap_files: int = 20,
    url_validator: Optional[Callable[[str], None]] = None,
) -> List[str]:
    """嘗試 ``/sitemap.xml`` 與 ``/sitemap_index.xml``，遞迴解析索引型 sitemap。

    回傳的 URL 已去重；不在這裡套用 same-origin/include/exclude，由呼叫方處理。
    """
    _check_runtime()
    h = dict(DEFAULT_HEADERS)
    if headers:
        h.update(headers)
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    queue: deque[str] = deque([
        urljoin(base, "/sitemap.xml"),
        urljoin(base, "/sitemap_index.xml"),
    ])
    seen_sitemaps: Set[str] = set()
    urls: List[str] = []
    seen_urls: Set[str] = set()
    while queue and len(urls) < max_urls and len(seen_sitemaps) < max_sitemap_files:
        sm = queue.popleft()
        if sm in seen_sitemaps:
            continue
        seen_sitemaps.add(sm)
        try:
            resp = _request_get(
                sm, headers=h, timeout=timeout, verify_tls=verify_tls, url_validator=url_validator
            )
        except Exception:  # noqa: BLE001
            continue
        if resp.status_code != 200 or not resp.text.strip():
            continue
        try:
            soup = BeautifulSoup(resp.text, "xml")
        except Exception:  # noqa: BLE001
            continue
        is_index = bool(soup.find("sitemapindex"))
        for loc in soup.find_all("loc"):
            u = (loc.get_text() or "").strip()
            if not u:
                continue
            if is_index:
                queue.append(u)
            else:
                if u in seen_urls:
                    continue
                seen_urls.add(u)
                urls.append(u)
                if len(urls) >= max_urls:
                    break
    return urls


def _compile_patterns(patterns: Optional[Iterable[str]]) -> List[re.Pattern[str]]:
    compiled: List[re.Pattern[str]] = []
    for pattern in patterns or []:
        text = (pattern or "").strip()
        if not text:
            continue
        try:
            compiled.append(re.compile(text))
        except re.error:
            # 非合法正則時退化為子字串比對
            compiled.append(re.compile(re.escape(text)))
    return compiled


def _url_allowed_by_path_rules(
    url: str,
    include: List[re.Pattern[str]],
    exclude: List[re.Pattern[str]],
) -> bool:
    """以 include / exclude 正則過濾 URL（比對完整 URL）。

    - 有 include 規則時，URL 必須命中至少一條才納入。
    - 命中任一 exclude 規則則排除（exclude 優先於 include）。
    """
    if any(pattern.search(url) for pattern in exclude):
        return False
    if include and not any(pattern.search(url) for pattern in include):
        return False
    return True


def scan_site(
    start_url: str,
    *,
    max_pages: int = 30,
    max_depth: int = 2,
    same_origin: bool = True,
    detectors: Optional[Iterable[BaseDetector]] = None,
    respect_robots: bool = True,
    delay: float = 0.5,
    timeout: float = 10.0,
    headers: Optional[dict] = None,
    verify_tls: bool = True,
    issues: Optional[List[ScanIssue]] = None,
    stats: Optional[dict] = None,
    preview: Optional[dict] = None,
    use_sitemap: bool = False,
    include_patterns: Optional[Iterable[str]] = None,
    exclude_patterns: Optional[Iterable[str]] = None,
    url_validator: Optional[Callable[[str], None]] = None,
) -> List[Finding]:
    """以 BFS 走訪同網域連結並掃描每個頁面與可下載文件。

    - ``use_sitemap=True``：先嘗試 ``/sitemap.xml``，將其中 URL 全部加入佇列。
    - ``include_patterns`` / ``exclude_patterns``：以正則（或子字串）限制要掃描的
      URL，例如只掃 ``/news/`` 或排除 ``/login``。exclude 優先於 include；
      起始網址不受規則限制，必定掃描。
    - 下載連結會自動辨識並分析：PDF / Word / Excel / OpenDocument /
      **ZIP 壓縮包**（遞迴解開成員）/ CSV / JSON / 純文字等。
    - HTML 內含 ``iframe``、``embed``、``object``、``link rel=alternate`` 等
      也會視為下游連結。
    """
    _check_runtime()
    h = dict(DEFAULT_HEADERS)
    if headers:
        h.update(headers)
    user_agent = h.get("User-Agent", "*")

    include = _compile_patterns(include_patterns)
    exclude = _compile_patterns(exclude_patterns)

    start_origin = urlparse(start_url).netloc
    visited: Set[str] = set()
    queue: deque[tuple[str, int]] = deque([(start_url, 0)])
    robots_cache: dict = {}
    findings: List[Finding] = []
    pages_scanned = 0
    html_scanned = 0
    documents_scanned = 0
    archives_scanned = 0
    text_scanned = 0
    sitemap_seeded = 0
    bytes_total = 0

    if use_sitemap:
        try:
            sm_urls = discover_sitemap_urls(
                start_url, timeout=timeout, headers=h, verify_tls=verify_tls,
                max_urls=max(max_pages * 4, 200),
                url_validator=url_validator,
            )
        except Exception:  # noqa: BLE001
            sm_urls = []
        for u in sm_urls:
            if same_origin and urlparse(u).netloc != start_origin:
                continue
            if u in visited:
                continue
            if not _url_allowed_by_path_rules(u, include, exclude):
                continue
            queue.append((u, 0))
            sitemap_seeded += 1

    while queue and pages_scanned < max_pages:
        url, depth = queue.popleft()
        if url in visited:
            continue
        visited.add(url)
        if url_validator:
            url_validator(url)
        if respect_robots and not _allowed_by_robots(url, user_agent, robots_cache):
            log.info("robots.txt 拒絕掃描 %s", url)
            if issues is not None:
                issues.append(ScanIssue(url, "robots.txt 拒絕掃描"))
            continue
        try:
            resp = _request_get(
                url, headers=h, timeout=timeout, verify_tls=verify_tls, url_validator=url_validator
            )
            resp.raise_for_status()
        except Exception as exc:  # noqa: BLE001
            log.warning("抓取 %s 失敗：%s", url, exc)
            if issues is not None:
                issues.append(ScanIssue(url, f"抓取失敗：{exc}"))
            continue

        pages_scanned += 1
        content_type = resp.headers.get("Content-Type", "")
        data = resp.content
        bytes_total += len(data)
        doc_ext = _resolve_document_ext(url, content_type, data)

        if doc_ext:
            findings.extend(
                _scan_response_as_document(
                    data, url, doc_ext,
                    detectors=detectors, issues=issues, preview=preview, stats=stats,
                )
            )
            documents_scanned += 1
        elif _is_archive_response(url, content_type, data):
            findings.extend(
                _scan_response_as_archive(
                    data, url,
                    detectors=detectors, issues=issues, preview=preview, stats=stats,
                )
            )
            archives_scanned += 1
        elif "html" in content_type:
            html_scanned += 1
            text = _html_to_text(resp.text)
            findings.extend(detect_in_text(text, detectors=detectors, source=url))
            if preview is not None and text:
                preview[url] = text
            for link in _extract_links(url, resp.text):
                if same_origin and urlparse(link).netloc != start_origin:
                    continue
                if link in visited:
                    continue
                if not _url_allowed_by_path_rules(link, include, exclude):
                    continue
                if depth < max_depth or is_downloadable_url(link):
                    queue.append((link, depth + 1))
        elif "text" in content_type or "json" in content_type or is_textual_url(url):
            text_scanned += 1
            findings.extend(detect_in_text(resp.text, detectors=detectors, source=url))
            if preview is not None and resp.text:
                preview[url] = resp.text

        if delay > 0:
            time.sleep(delay)

    if stats is not None:
        stats["pages_scanned"] = pages_scanned
        stats["html_scanned"] = html_scanned
        stats["documents_scanned"] = documents_scanned
        stats["archives_scanned"] = archives_scanned
        stats["text_scanned"] = text_scanned
        stats["sitemap_seeded"] = sitemap_seeded
        stats["bytes_total"] = bytes_total
        stats["start_url"] = start_url
    return findings


def _request_get(
    url: str,
    *,
    headers: dict,
    timeout: float,
    verify_tls: bool,
    url_validator: Optional[Callable[[str], None]],
):
    current_url = url
    for _ in range(6):
        if url_validator:
            url_validator(current_url)
        response = requests.get(
            current_url,
            headers=headers,
            timeout=timeout,
            verify=verify_tls,
            allow_redirects=False,
        )
        if response.status_code not in {301, 302, 303, 307, 308}:
            return response
        location = response.headers.get("Location")
        if not location:
            return response
        current_url = urljoin(current_url, location)
    raise RuntimeError("網站重新導向次數過多")
