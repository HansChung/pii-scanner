"""Office / 開放文件格式掃描測試。"""

from io import BytesIO

import pytest
from openpyxl import Workbook

from pii_scanner.scanners.document_reader import extract_document_segments
from pii_scanner.scanners.file_scanner import scan_bytes


def _make_xlsx_bytes() -> bytes:
    wb = Workbook()
    ws1 = wb.active
    ws1.title = "學生名單"
    ws1.append(["姓名", "手機"])
    ws1.append(["王小明", "0912345678"])
    ws2 = wb.create_sheet("職員")
    ws2.append(["Email"])
    ws2.append(["test@example.com"])
    buf = BytesIO()
    wb.save(buf)
    return buf.getvalue()


def test_xlsx_multi_sheet_segments():
    data = _make_xlsx_bytes()
    segments = extract_document_segments(data, "sample.xlsx")
    sources = {s.source for s in segments}
    assert "sample.xlsx#學生名單" in sources
    assert "sample.xlsx#職員" in sources
    student = next(s for s in segments if "學生名單" in s.source)
    assert "0912345678" in student.text


def test_scan_xlsx_finds_pii_per_sheet():
    data = _make_xlsx_bytes()
    findings = scan_bytes(data, "sample.xlsx")
    sources = {f.source for f in findings}
    assert any("學生名單" in s for s in sources)
    assert any(f.detector == "taiwan_mobile" for f in findings)
    assert any(f.detector == "email" for f in findings)


def test_scan_plain_text_still_works():
    raw = "手機 0912345678".encode("utf-8")
    findings = scan_bytes(raw, "note.txt")
    assert any(f.detector == "taiwan_mobile" for f in findings)


def test_unsupported_extension():
    from pii_scanner.scanners.document_reader import DocumentReadError

    with pytest.raises(DocumentReadError, match="不支援"):
        extract_document_segments(b"data", "file.pdf")
