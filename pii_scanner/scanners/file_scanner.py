"""檔案 / 目錄掃描器。

支援純文字、CSV、JSON、Markdown、HTML、原始碼等可解碼為 UTF-8/Big5 的檔案；
二進位檔會自動跳過。
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, Iterator, List, Optional

from ..detectors import detect_in_text
from ..detectors.base import BaseDetector, Finding

DEFAULT_TEXT_SUFFIXES = {
    ".txt", ".md", ".rst", ".csv", ".tsv", ".log", ".json", ".jsonl",
    ".yaml", ".yml", ".xml", ".html", ".htm", ".css", ".js", ".ts",
    ".tsx", ".jsx", ".py", ".java", ".go", ".rb", ".rs", ".c", ".cc",
    ".cpp", ".h", ".hpp", ".php", ".sql", ".sh", ".ini", ".conf", ".env",
}

DEFAULT_IGNORES = {".git", ".hg", ".svn", "__pycache__", "node_modules", ".venv", "venv"}

MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB 上限，避免一次吃下大檔


def _read_text(path: Path, max_bytes: int = MAX_FILE_BYTES) -> Optional[str]:
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size == 0:
        return ""
    data = path.read_bytes()[:max_bytes]
    for enc in ("utf-8", "utf-8-sig", "big5", "cp950", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return None


def scan_file(
    path: str | os.PathLike,
    *,
    detectors: Optional[Iterable[BaseDetector]] = None,
    max_bytes: int = MAX_FILE_BYTES,
) -> List[Finding]:
    """掃描單一檔案；遇到無法解碼的二進位檔回傳空清單。"""
    p = Path(path)
    text = _read_text(p, max_bytes=max_bytes)
    if text is None:
        return []
    return detect_in_text(text, detectors=detectors, source=str(p))


def iter_files(
    root: str | os.PathLike,
    *,
    suffixes: Optional[Iterable[str]] = None,
    ignores: Optional[Iterable[str]] = None,
) -> Iterator[Path]:
    """遞迴列出待掃描檔案。"""
    suffixes_set = {s.lower() for s in (suffixes or DEFAULT_TEXT_SUFFIXES)}
    ignores_set = set(ignores or DEFAULT_IGNORES)
    root_path = Path(root)
    if root_path.is_file():
        yield root_path
        return
    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in ignores_set and not d.startswith(".")]
        for fn in filenames:
            p = Path(dirpath) / fn
            if not suffixes_set or p.suffix.lower() in suffixes_set:
                yield p


def scan_directory(
    root: str | os.PathLike,
    *,
    detectors: Optional[Iterable[BaseDetector]] = None,
    suffixes: Optional[Iterable[str]] = None,
    ignores: Optional[Iterable[str]] = None,
    max_bytes: int = MAX_FILE_BYTES,
) -> List[Finding]:
    """遞迴掃描整個目錄。"""
    findings: List[Finding] = []
    for p in iter_files(root, suffixes=suffixes, ignores=ignores):
        findings.extend(scan_file(p, detectors=detectors, max_bytes=max_bytes))
    return findings
