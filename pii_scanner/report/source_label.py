"""將 Finding.source 解析為易讀的檔案 / 位置標籤。"""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Iterable, List, Optional
from urllib.parse import urlparse

from ..detectors.base import Finding
from ..scanners.document_reader import DOCUMENT_SUFFIXES


def source_kind(file_key: str) -> str:
    """來源類型：web_page / web_document / file / inline。"""
    if file_key == "<inline>":
        return "inline"
    if "://" in file_key:
        path = urlparse(file_key).path
        if Path(path).suffix.lower() in DOCUMENT_SUFFIXES:
            return "web_document"
        return "web_page"
    return "file"


SOURCE_KIND_LABELS = {
    "web_page": "網頁",
    "web_document": "下載文件",
    "file": "本機檔案",
    "inline": "內嵌",
}


def source_kind_label(kind: str) -> str:
    return SOURCE_KIND_LABELS.get(kind, kind)


def split_source_label(source: Optional[str]) -> dict:
    """將 source 拆成檔案與細部位置（工作表、頁碼等）。

    範例：
    - ``report.xlsx#學生名單`` → file=report.xlsx, location=學生名單
    - ``/data/logs/a.txt`` → file=/data/logs/a.txt, location=None
    - ``https://x.com/a.pdf#page=2`` → file=URL, location=page=2
    """
    if not source:
        return {"file": None, "location": None, "display": "<inline>"}

    if "#" in source:
        file_part, location = source.split("#", 1)
        return {
            "file": file_part or source,
            "location": location or None,
            "display": source,
        }

    return {"file": source, "location": None, "display": source}


def _location_label(location: Optional[str]) -> str:
    if not location:
        return "（全文）"
    if location.startswith("page="):
        return f"第 {location[5:]} 頁"
    return location


def summarize_by_source(findings: Iterable[Finding]) -> dict[str, int]:
    """各完整 source（含 #工作表 / #page）的命中數。"""
    counts: dict[str, int] = defaultdict(int)
    for f in findings:
        key = f.source or "<inline>"
        counts[key] += 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def summarize_by_file(findings: Iterable[Finding]) -> List[dict]:
    """依檔案（source 的 # 前段）彙總命中，並列出各位置明細。"""
    by_file: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for f in findings:
        parts = split_source_label(f.source)
        file_key = parts["file"] or "<inline>"
        loc_key = parts["location"] or ""
        by_file[file_key][loc_key] += 1

    rows: List[dict] = []
    for file_key in sorted(by_file, key=lambda k: (-sum(by_file[k].values()), k)):
        loc_counts = by_file[file_key]
        total = sum(loc_counts.values())
        locations = [
            {
                "location": loc or None,
                "label": _location_label(loc or None),
                "count": cnt,
            }
            for loc, cnt in sorted(
                loc_counts.items(),
                key=lambda kv: (-kv[1], kv[0]),
            )
        ]
        kind = source_kind(file_key)
        rows.append(
            {
                "file": file_key,
                "total": total,
                "locations": locations,
                "kind": kind,
                "kind_label": source_kind_label(kind),
                "display": format_file_display_name(file_key),
            }
        )
    return rows


def format_file_display_name(file_key: str) -> str:
    """網址顯示路徑末段檔名；一般網頁則顯示路徑或網域。"""
    if "://" not in file_key:
        return Path(file_key).name or file_key
    parsed = urlparse(file_key)
    path = parsed.path
    name = path.rsplit("/", 1)[-1]
    if name:
        return name
    return parsed.netloc or file_key
