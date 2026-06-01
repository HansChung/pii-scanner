"""試算表文字擷取（表頭 / 無表頭姓名）測試。"""

from io import BytesIO

from openpyxl import Workbook

from pii_scanner.scanners.document_reader import extract_document_segments
from pii_scanner.scanners.file_scanner import scan_bytes
from pii_scanner.scanners.spreadsheet_text import rows_to_scan_text


def test_with_header_labels_name_column():
    text = rows_to_scan_text(
        [
            ["姓名", "手機"],
            ["王小明", "0912345678"],
        ],
        max_rows=100,
    )
    assert "姓名：王小明" in text
    assert "手機：0912345678" in text


def test_without_header_infers_name_prefix():
    text = rows_to_scan_text(
        [
            ["王小明", "0912345678"],
            ["陳小華", "0922123456"],
        ],
        max_rows=100,
    )
    assert "姓名：王小明" in text
    assert "姓名：陳小華" in text


def test_scan_xlsx_without_header_finds_name():
    wb = Workbook()
    ws = wb.active
    ws.append(["王小明", "0912345678", "test@example.com"])
    buf = BytesIO()
    wb.save(buf)

    findings = scan_bytes(buf.getvalue(), "no_header.xlsx")
    assert any(f.value == "王小明" and f.category == "name" for f in findings)


def test_scan_xlsx_with_header_still_finds_name():
    wb = Workbook()
    ws = wb.active
    ws.append(["姓名", "手機"])
    ws.append(["王小明", "0912345678"])
    buf = BytesIO()
    wb.save(buf)

    segments = extract_document_segments(buf.getvalue(), "with_header.xlsx")
    assert any("姓名：王小明" in s.text for s in segments)
