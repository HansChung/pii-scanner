from __future__ import annotations

import csv
from pathlib import Path

from docx import Document
from openpyxl import load_workbook
from pptx import Presentation
from pypdf import PdfReader

from pii_scanner.scanners.spreadsheet_text import labeled_rows

from .models import ExtractedText

# 表格類（Excel、CSV、Word／PowerPoint 表格）逐列轉文字時會先找表頭，
# 資料列寫成「欄名：值」並以 tab 分隔，讓學號、姓名等需要關鍵字的規則在表格裡也抓得到。


def extract_text(path: Path, extension: str) -> list[ExtractedText]:
    extension = extension.lower()
    if extension == ".pdf":
        return _extract_pdf(path)
    if extension == ".docx":
        return _extract_docx(path)
    if extension == ".pptx":
        return _extract_pptx(path)
    if extension == ".xlsx":
        return _extract_xlsx(path)
    if extension == ".csv":
        return _extract_csv(path)
    if extension == ".txt":
        return _extract_txt(path)
    return []


def _extract_pdf(path: Path) -> list[ExtractedText]:
    reader = PdfReader(str(path))
    chunks = []
    for index, page in enumerate(reader.pages, start=1):
        text = page.extract_text() or ""
        if text.strip():
            chunks.append(ExtractedText(text=text, location=f"第 {index} 頁"))
    return chunks


def _extract_docx(path: Path) -> list[ExtractedText]:
    doc = Document(str(path))
    chunks = []
    for index, paragraph in enumerate(doc.paragraphs, start=1):
        text = paragraph.text.strip()
        if text:
            chunks.append(ExtractedText(text=text, location=f"段落 {index}"))
    for table_index, table in enumerate(doc.tables, start=1):
        rows = ([cell.text.strip() for cell in row.cells] for row in table.rows)
        chunks.extend(
            ExtractedText(text=row.text, location=f"表格 {table_index} 列 {row.row_number}")
            for row in labeled_rows(rows)
        )
    return chunks


def _extract_pptx(path: Path) -> list[ExtractedText]:
    prs = Presentation(str(path))
    chunks = []
    for slide_index, slide in enumerate(prs.slides, start=1):
        texts = []
        table_chunks = []
        table_index = 0
        for shape in slide.shapes:
            if getattr(shape, "has_table", False):
                table_index += 1
                rows = ([cell.text.strip() for cell in row.cells] for row in shape.table.rows)
                table_chunks.extend(
                    ExtractedText(
                        text=row.text,
                        location=f"投影片 {slide_index} 表格 {table_index} 列 {row.row_number}",
                    )
                    for row in labeled_rows(rows)
                )
            elif hasattr(shape, "text") and shape.text:
                texts.append(shape.text)
        if texts:
            chunks.append(ExtractedText(text="\n".join(texts), location=f"投影片 {slide_index}"))
        chunks.extend(table_chunks)
    return chunks


def _extract_xlsx(path: Path) -> list[ExtractedText]:
    wb = load_workbook(str(path), read_only=True, data_only=True)
    chunks = []
    for sheet in wb.worksheets:
        chunks.extend(
            ExtractedText(text=row.text, location=f"工作表 {sheet.title} 第 {row.row_number} 列")
            for row in labeled_rows(sheet.iter_rows(values_only=True))
        )
    return chunks


def _extract_csv(path: Path) -> list[ExtractedText]:
    chunks = []
    with path.open("r", encoding="utf-8-sig", newline="", errors="replace") as handle:
        chunks.extend(
            ExtractedText(text=row.text, location=f"CSV 第 {row.row_number} 列")
            for row in labeled_rows(csv.reader(handle))
        )
    return chunks


def _extract_txt(path: Path) -> list[ExtractedText]:
    chunks = []
    with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
        for line_index, line in enumerate(handle, start=1):
            text = line.strip()
            if text:
                chunks.append(ExtractedText(text=text, location=f"第 {line_index} 行"))
    return chunks

