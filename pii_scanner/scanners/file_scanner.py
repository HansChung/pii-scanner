"""檔案 / 目錄掃描器。

支援：
- 純文字：TXT、CSV、JSON、HTML、原始碼等
- Excel (.xlsx/.xlsm)：逐工作表掃描
- PDF (.pdf)：逐頁掃描
- 開放文件：ODS、ODT、DOCX
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, Iterator, List, Optional

from ..detectors import detect_in_text
from ..detectors.base import BaseDetector, Finding
from .document_reader import (
    DOCUMENT_SUFFIXES,
    DocumentReadError,
    extract_document_segments,
    is_document_file,
)

DEFAULT_TEXT_SUFFIXES = {
    ".txt", ".md", ".rst", ".csv", ".tsv", ".log", ".json", ".jsonl",
    ".yaml", ".yml", ".xml", ".html", ".htm", ".css", ".js", ".ts",
    ".tsx", ".jsx", ".py", ".java", ".go", ".rb", ".rs", ".c", ".cc",
    ".cpp", ".h", ".hpp", ".php", ".sql", ".sh", ".ini", ".conf", ".env",
}

DEFAULT_SCAN_SUFFIXES = DEFAULT_TEXT_SUFFIXES | DOCUMENT_SUFFIXES

DEFAULT_IGNORES = {".git", ".hg", ".svn", "__pycache__", "node_modules", ".venv", "venv"}

MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB 上限，避免一次吃下大檔


def _read_text_bytes(data: bytes) -> Optional[str]:
    for enc in ("utf-8", "utf-8-sig", "big5", "cp950", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return None


def _read_text(path: Path, max_bytes: int = MAX_FILE_BYTES) -> Optional[str]:
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size == 0:
        return ""
    data = path.read_bytes()[:max_bytes]
    return _read_text_bytes(data)


def scan_bytes(
    data: bytes,
    filename: str,
    *,
    detectors: Optional[Iterable[BaseDetector]] = None,
) -> List[Finding]:
    """掃描記憶體中的檔案內容（文字檔或 Office/開放文件）。"""
    name = filename or "upload"
    ext = Path(name).suffix.lower()

    if ext in DOCUMENT_SUFFIXES:
        segments = extract_document_segments(data, name)
        findings: List[Finding] = []
        for seg in segments:
            findings.extend(detect_in_text(seg.text, detectors=detectors, source=seg.source))
        return findings

    text = _read_text_bytes(data)
    if text is None:
        raise DocumentReadError(
            "無法解碼此檔案；請上傳文字檔或支援的 Office/開放文件格式"
        )
    return detect_in_text(text, detectors=detectors, source=name)


def scan_file(
    path: str | os.PathLike,
    *,
    detectors: Optional[Iterable[BaseDetector]] = None,
    max_bytes: int = MAX_FILE_BYTES,
) -> List[Finding]:
    """掃描單一檔案；遇到無法解碼的二進位檔回傳空清單。"""
    p = Path(path)
    if is_document_file(p):
        try:
            data = p.read_bytes()[:max_bytes]
        except OSError:
            return []
        try:
            return scan_bytes(data, p.name, detectors=detectors)
        except DocumentReadError:
            return []

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
    suffixes_set = {s.lower() for s in (suffixes or DEFAULT_SCAN_SUFFIXES)}
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
