"""上傳內容文字擷取（供 Azure AI 增強分析）。"""
from __future__ import annotations

from ..scanners.document_reader import DOCUMENT_SUFFIXES, extract_document_segments
from ..scanners.file_scanner import _read_text_bytes
from ..scanners.format_sniff import sniff_document_suffix
from ..settings import AI_MAX_CHARS


def text_from_upload(raw: bytes, filename: str) -> str:
    """自 uploaded bytes 擷取可供 AI 分析的文字。"""
    name = filename or "upload"
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    sniffed = sniff_document_suffix(raw)
    doc_ext = sniffed or (f".{ext}" if ext else "")
    if doc_ext in DOCUMENT_SUFFIXES:
        segments = extract_document_segments(raw, name, ext=doc_ext)
        combined = "\n\n".join(s.text for s in segments)
        return combined[:AI_MAX_CHARS]
    plain = _read_text_bytes(raw)
    if plain is None:
        return ""
    return plain[:AI_MAX_CHARS]
