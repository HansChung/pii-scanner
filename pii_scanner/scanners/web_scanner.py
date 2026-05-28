"""網站掃描器：抓取 URL，剝去 HTML 後跑 PII 偵測。

預設遵守同一網域、深度限制與 robots.txt。網路存取使用 requests，
若環境無安裝 requests / beautifulsoup4，會於匯入時報出明確訊息。

若 URL 或頁面中的下載連結指向 PDF、Word、Excel 等支援格式，
會以與檔案上傳相同的方式解析並掃描（逐頁 / 逐工作表）。
"""
from __future__ import annotations

import logging
import re
import time
from collections import deque
from pathlib import Path
from typing import Iterable, List, Optional, Set
from urllib.parse import unquote, urljoin, urlparse
from urllib.robotparser import RobotFileParser

from ..detectors import detect_in_text
from ..detectors.base import BaseDetector, Finding
from .document_reader import DOCUMENT_SUFFIXES, DocumentReadError, extract_document_segments
from .file_scanner import MAX_FILE_BYTES, scan_bytes
from .format_sniff import sniff_document_suffix

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

# Content-Type → 副檔名（部分伺服器未在 URL 帶副檔名時使用）
DOCUMENT_CONTENT_TYPES = {
    "application/pdf": ".pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "application/vnd.ms-excel": ".xls",
    "application/vnd.oasis.opendocument.text": ".odt",
    "application/vnd.oasis.opendocument.spreadsheet": ".ods",
}


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


def _filename_from_url(url: str, doc_ext: Optional[str] = None) -> str:
    path = unquote(urlparse(url).path)
    name = Path(path).name or "download"
    if doc_ext and not name.lower().endswith(doc_ext):
        name = f"{Path(name).stem}{doc_ext}"
    return name


def _resolve_document_ext(url: str, content_type: str, data: bytes) -> Optional[str]:
    """依內容魔術位元組、URL 副檔名或 Content-Type 判斷是否為可掃描文件。"""
    sniffed = sniff_document_suffix(data[:65536])
    if sniffed:
        return sniffed
    suffix = _suffix_from_url_path(url)
    if suffix:
        return suffix
    ct = content_type.split(";", 1)[0].strip().lower()
    return DOCUMENT_CONTENT_TYPES.get(ct)


def _document_segments_to_text(data: bytes, url: str, doc_ext: str) -> str:
    filename = _filename_from_url(url, doc_ext)
    if len(data) > MAX_FILE_BYTES:
        data = data[:MAX_FILE_BYTES]
    segments = extract_document_segments(data, filename, ext=doc_ext)
    parts = [seg.text for seg in segments if seg.text.strip()]
    return "\n\n".join(parts)


def _scan_response_as_document(
    data: bytes,
    url: str,
    doc_ext: str,
    *,
    detectors: Optional[Iterable[BaseDetector]] = None,
) -> List[Finding]:
    if len(data) > MAX_FILE_BYTES:
        log.warning("文件 %s 超過 %s bytes，已截斷掃描", url, MAX_FILE_BYTES)
        data = data[:MAX_FILE_BYTES]
    filename = _filename_from_url(url, doc_ext)
    try:
        return scan_bytes(data, filename, detectors=detectors)
    except DocumentReadError as exc:
        log.warning("無法解析文件 %s：%s", url, exc)
        return []


def fetch_url_text(
    url: str,
    *,
    timeout: float = 10.0,
    headers: Optional[dict] = None,
    verify_tls: bool = True,
) -> str:
    """抓取 URL 並回傳純文字（供 AI 增強；含 PDF/Word 等文件文字擷取）。"""
    _check_runtime()
    h = dict(DEFAULT_HEADERS)
    if headers:
        h.update(headers)
    resp = requests.get(url, headers=h, timeout=timeout, verify=verify_tls)
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
) -> List[Finding]:
    """抓取單一 URL 並掃描（HTML 頁面或直接指向 PDF/Word/Excel 等文件 URL）。"""
    _check_runtime()
    h = dict(DEFAULT_HEADERS)
    if headers:
        h.update(headers)
    resp = requests.get(url, headers=h, timeout=timeout, verify=verify_tls)
    resp.raise_for_status()
    content_type = resp.headers.get("Content-Type", "")
    data = resp.content
    doc_ext = _resolve_document_ext(url, content_type, data)
    if doc_ext:
        return _scan_response_as_document(data, url, doc_ext, detectors=detectors)
    if "html" in content_type or "xml" in content_type:
        text = _html_to_text(resp.text)
    else:
        text = resp.text
    return detect_in_text(text, detectors=detectors, source=url)


def _extract_links(base_url: str, html: str) -> List[str]:
    soup = BeautifulSoup(html, "html.parser")
    urls = []
    for a in soup.find_all("a", href=True):
        u = urljoin(base_url, a["href"]).split("#", 1)[0]
        if u.startswith("http://") or u.startswith("https://"):
            urls.append(u)
    return urls


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
) -> List[Finding]:
    """以 BFS 走訪同網域連結並掃描每個頁面與可下載文件。"""
    _check_runtime()
    h = dict(DEFAULT_HEADERS)
    if headers:
        h.update(headers)
    user_agent = h.get("User-Agent", "*")

    start_origin = urlparse(start_url).netloc
    visited: Set[str] = set()
    queue: deque[tuple[str, int]] = deque([(start_url, 0)])
    robots_cache: dict = {}
    findings: List[Finding] = []
    pages_scanned = 0

    while queue and pages_scanned < max_pages:
        url, depth = queue.popleft()
        if url in visited:
            continue
        visited.add(url)
        if respect_robots and not _allowed_by_robots(url, user_agent, robots_cache):
            log.info("robots.txt 拒絕掃描 %s", url)
            continue
        try:
            resp = requests.get(url, headers=h, timeout=timeout, verify=verify_tls)
            resp.raise_for_status()
        except Exception as exc:  # noqa: BLE001
            log.warning("抓取 %s 失敗：%s", url, exc)
            continue

        pages_scanned += 1
        content_type = resp.headers.get("Content-Type", "")
        data = resp.content
        doc_ext = _resolve_document_ext(url, content_type, data)
        if doc_ext:
            findings.extend(
                _scan_response_as_document(data, url, doc_ext, detectors=detectors)
            )
        elif "html" in content_type:
            text = _html_to_text(resp.text)
            findings.extend(detect_in_text(text, detectors=detectors, source=url))
            for link in _extract_links(url, resp.text):
                if same_origin and urlparse(link).netloc != start_origin:
                    continue
                if link in visited:
                    continue
                # 已達深度上限時仍跟進頁面上的文件下載連結（不再展開 HTML 子頁）
                if depth < max_depth or is_document_url(link):
                    queue.append((link, depth + 1))
        elif "text" in content_type or "json" in content_type:
            findings.extend(detect_in_text(resp.text, detectors=detectors, source=url))

        if delay > 0:
            time.sleep(delay)

    return findings
