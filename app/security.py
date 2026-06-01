from __future__ import annotations

import re
from pathlib import Path

try:
    import magic
except Exception:  # pragma: no cover - optional native dependency
    magic = None


EXTENSION_MIME_PREFIXES = {
    ".pdf": ("application/pdf",),
    ".docx": (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/zip",
    ),
    ".pptx": (
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/zip",
    ),
    ".xlsx": (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/zip",
    ),
    ".csv": ("text/csv", "text/plain", "application/vnd.ms-excel"),
    ".txt": ("text/plain",),
    ".jpg": ("image/jpeg",),
    ".jpeg": ("image/jpeg",),
    ".png": ("image/png",),
}


def normalize_extension(filename: str) -> str:
    return Path(filename).suffix.lower()


def safe_filename(filename: str) -> str:
    stem = Path(filename).stem
    ext = normalize_extension(filename)
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._")
    return f"{cleaned or 'upload'}{ext}"


def sniff_mime(path: Path, fallback: str = "") -> str:
    if magic is not None:
        try:
            return str(magic.from_file(str(path), mime=True))
        except Exception:
            pass
    return fallback or "application/octet-stream"


def mime_matches_extension(extension: str, mime_type: str) -> bool:
    allowed = EXTENSION_MIME_PREFIXES.get(extension.lower())
    if not allowed:
        return False
    if mime_type in allowed:
        return True
    if extension in {".csv", ".txt"} and mime_type.startswith("text/"):
        return True
    return False

