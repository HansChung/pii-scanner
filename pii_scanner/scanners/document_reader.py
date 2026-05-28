"""Office / 開放文件格式文字擷取。

支援：
- Excel (.xlsx, .xlsm)：逐工作表擷取儲存格
- OpenDocument 試算表 (.ods)：逐工作表
- OpenDocument 文字 (.odt)、Word (.docx)：段落與表格
"""
from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Callable, Iterable, List, Optional

from ..settings import MAX_DOCUMENT_ROWS, MAX_DOCUMENT_SHEETS

# 二進位文件副檔名 → 擷取函式
EXCEL_SUFFIXES = {".xlsx", ".xlsm"}
ODS_SUFFIXES = {".ods"}
ODT_SUFFIXES = {".odt"}
DOCX_SUFFIXES = {".docx"}

DOCUMENT_SUFFIXES = EXCEL_SUFFIXES | ODS_SUFFIXES | ODT_SUFFIXES | DOCX_SUFFIXES


@dataclass(frozen=True)
class DocumentSegment:
    """文件中的一段可掃描文字（例如 Excel 的單一工作表）。"""

    source: str
    text: str


class DocumentReadError(Exception):
    """無法解析文件。"""


def is_document_file(path: str | Path) -> bool:
    return Path(path).suffix.lower() in DOCUMENT_SUFFIXES


def _cell_str(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _rows_to_text(rows: Iterable[Iterable[object]]) -> str:
    lines: List[str] = []
    count = 0
    for row in rows:
        if count >= MAX_DOCUMENT_ROWS:
            lines.append("…(已達列數上限，其餘略過)")
            break
        cells = [_cell_str(c) for c in row]
        line = "\t".join(c for c in cells if c)
        if line:
            lines.append(line)
            count += 1
    return "\n".join(lines)


def _extract_xlsx(data: bytes, filename: str) -> List[DocumentSegment]:
    try:
        from openpyxl import load_workbook
    except ImportError as exc:
        raise DocumentReadError("缺少 openpyxl，無法讀取 Excel") from exc

    try:
        wb = load_workbook(BytesIO(data), read_only=True, data_only=True)
    except Exception as exc:
        raise DocumentReadError(f"無法解析 Excel：{exc}") from exc

    segments: List[DocumentSegment] = []
    try:
        for idx, ws in enumerate(wb.worksheets):
            if idx >= MAX_DOCUMENT_SHEETS:
                break
            text = _rows_to_text(ws.iter_rows(values_only=True))
            if text.strip():
                sheet = ws.title or f"Sheet{idx + 1}"
                segments.append(DocumentSegment(source=f"{filename}#{sheet}", text=text))
    finally:
        wb.close()
    return segments


def _odf_cell_text(cell) -> str:
    from odf.text import P

    parts: List[str] = []
    for p in cell.getElementsByType(P):
        parts.append("".join(node.data for node in p.childNodes if node.nodeType == 3))
    return "".join(parts).strip()


def _extract_ods(data: bytes, filename: str) -> List[DocumentSegment]:
    try:
        from odf.opendocument import load
        from odf.table import Table, TableCell, TableRow
    except ImportError as exc:
        raise DocumentReadError("缺少 odfpy，無法讀取 ODS") from exc

    try:
        doc = load(BytesIO(data))
    except Exception as exc:
        raise DocumentReadError(f"無法解析 ODS：{exc}") from exc

    segments: List[DocumentSegment] = []
    for idx, table in enumerate(doc.getElementsByType(Table)):
        if idx >= MAX_DOCUMENT_SHEETS:
            break
        name = table.getAttribute("name") or f"Sheet{idx + 1}"

        def _rows():
            row_count = 0
            for row in table.getElementsByType(TableRow):
                if row_count >= MAX_DOCUMENT_ROWS:
                    yield ["…(已達列數上限)"]
                    return
                cells = [_odf_cell_text(c) for c in row.getElementsByType(TableCell)]
                yield cells
                row_count += 1

        text = _rows_to_text(_rows())
        if text.strip():
            segments.append(DocumentSegment(source=f"{filename}#{name}", text=text))
    return segments


def _extract_odt(data: bytes, filename: str) -> List[DocumentSegment]:
    try:
        from odf.opendocument import load
        from odf.table import Table, TableCell, TableRow
        from odf.text import P
    except ImportError as exc:
        raise DocumentReadError("缺少 odfpy，無法讀取 ODT") from exc

    try:
        doc = load(BytesIO(data))
    except Exception as exc:
        raise DocumentReadError(f"無法解析 ODT：{exc}") from exc

    parts: List[str] = []
    for p in doc.getElementsByType(P):
        t = "".join(node.data for node in p.childNodes if node.nodeType == 3).strip()
        if t:
            parts.append(t)

    for table in doc.getElementsByType(Table):
        for row in table.getElementsByType(TableRow):
            cells = [_odf_cell_text(c) for c in row.getElementsByType(TableCell)]
            line = "\t".join(c for c in cells if c)
            if line:
                parts.append(line)

    text = "\n".join(parts)
    if not text.strip():
        return []
    return [DocumentSegment(source=filename, text=text)]


def _extract_docx(data: bytes, filename: str) -> List[DocumentSegment]:
    try:
        from docx import Document
    except ImportError as exc:
        raise DocumentReadError("缺少 python-docx，無法讀取 DOCX") from exc

    try:
        doc = Document(BytesIO(data))
    except Exception as exc:
        raise DocumentReadError(f"無法解析 DOCX：{exc}") from exc

    parts: List[str] = []
    for para in doc.paragraphs:
        t = para.text.strip()
        if t:
            parts.append(t)
    for table in doc.tables:
        for row in table.rows:
            cells = [c.text.strip() for c in row.cells if c.text.strip()]
            if cells:
                parts.append("\t".join(cells))

    text = "\n".join(parts)
    if not text.strip():
        return []
    return [DocumentSegment(source=filename, text=text)]


_EXTRACTORS: dict[str, Callable[[bytes, str], List[DocumentSegment]]] = {}
for suf in EXCEL_SUFFIXES:
    _EXTRACTORS[suf] = _extract_xlsx
for suf in ODS_SUFFIXES:
    _EXTRACTORS[suf] = _extract_ods
for suf in ODT_SUFFIXES:
    _EXTRACTORS[suf] = _extract_odt
for suf in DOCX_SUFFIXES:
    _EXTRACTORS[suf] = _extract_docx


def supported_document_formats() -> List[str]:
    return sorted(DOCUMENT_SUFFIXES)


def extract_document_segments(data: bytes, filename: str) -> List[DocumentSegment]:
    """依副檔名擷取文件各分頁/段落文字。"""
    ext = Path(filename).suffix.lower()
    fn = _EXTRACTORS.get(ext)
    if fn is None:
        raise DocumentReadError(
            f"不支援的文件格式 {ext}；支援：{', '.join(supported_document_formats())}"
        )
    segments = fn(data, filename)
    if not segments:
        raise DocumentReadError("文件內容為空或無可讀文字")
    return segments
