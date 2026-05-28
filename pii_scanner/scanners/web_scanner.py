"""網站掃描器：抓取 URL，剝去 HTML 後跑 PII 偵測。

預設遵守同一網域、深度限制與 robots.txt。網路存取使用 requests，
若環境無安裝 requests / beautifulsoup4，會於匯入時報出明確訊息。
"""
from __future__ import annotations

import logging
import re
import time
from collections import deque
from typing import Iterable, List, Optional, Set
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser

from ..detectors import detect_in_text
from ..detectors.base import BaseDetector, Finding

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


def fetch_url_text(
    url: str,
    *,
    timeout: float = 10.0,
    headers: Optional[dict] = None,
    verify_tls: bool = True,
) -> str:
    """抓取 URL 並回傳純文字（供 AI 增強）。"""
    _check_runtime()
    h = dict(DEFAULT_HEADERS)
    if headers:
        h.update(headers)
    resp = requests.get(url, headers=h, timeout=timeout, verify=verify_tls)
    resp.raise_for_status()
    content_type = resp.headers.get("Content-Type", "")
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
    """抓取單一 URL 並掃描。"""
    _check_runtime()
    h = dict(DEFAULT_HEADERS)
    if headers:
        h.update(headers)
    resp = requests.get(url, headers=h, timeout=timeout, verify=verify_tls)
    resp.raise_for_status()
    content_type = resp.headers.get("Content-Type", "")
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
    """以 BFS 走訪同網域連結並掃描每個頁面。"""
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
        if "html" in content_type:
            text = _html_to_text(resp.text)
            findings.extend(detect_in_text(text, detectors=detectors, source=url))
            if depth < max_depth:
                for link in _extract_links(url, resp.text):
                    if same_origin and urlparse(link).netloc != start_origin:
                        continue
                    if link not in visited:
                        queue.append((link, depth + 1))
        elif "text" in content_type or "json" in content_type:
            findings.extend(detect_in_text(resp.text, detectors=detectors, source=url))

        if delay > 0:
            time.sleep(delay)

    return findings
