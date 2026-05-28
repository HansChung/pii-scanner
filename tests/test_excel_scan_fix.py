"""文件格式 sniff 與 Excel 掃描修復測試。"""

from io import BytesIO

import pytest
from openpyxl import Workbook

from pii_scanner.scanners.document_reader import DocumentReadError, extract_document_segments
from pii_scanner.scanners.file_scanner import scan_bytes
from pii_scanner.scanners.format_sniff import sniff_document_suffix


def _make_student_xlsx() -> bytes:
    wb = Workbook()
    ws = wb.active
    ws.title = "學生個資總表"
    ws.append(
        ["姓名", "手機", "Email", "戶籍地址", "健保卡號"]
    )
    ws.append(
        [
            "王小明",
            "0912-345-678",
            "test001@mail.tku.edu.tw",
            "新北市淡水區英專路151號",
            "000012345678",
        ]
    )
    buf = BytesIO()
    wb.save(buf)
    return buf.getvalue()


def test_sniff_xlsx_magic():
    data = _make_student_xlsx()
    assert sniff_document_suffix(data) == ".xlsx"


def test_xlsx_without_extension_still_finds_pii():
    data = _make_student_xlsx()
    findings = scan_bytes(data, "upload")
    assert len(findings) >= 3
    assert any(f.detector == "taiwan_mobile" for f in findings)
    assert any(f.detector == "email" for f in findings)


def test_xlsx_with_wrong_xls_extension_still_finds_pii():
    data = _make_student_xlsx()
    findings = scan_bytes(data, "data.xls")
    assert any(f.detector == "taiwan_mobile" for f in findings)


def test_binary_garbage_not_silent_empty():
    data = _make_student_xlsx()
    # 模擬舊版：若當純文字解碼會回空結果；現在應走文件解析
    findings = scan_bytes(data, "notes.txt")
    assert len(findings) >= 3


def test_corrupt_binary_raises():
    with pytest.raises(DocumentReadError):
        scan_bytes(bytes(range(256)) * 4, "file.txt")


def test_multi_sheet_student_workbook():
    data = _make_student_xlsx()
    segments = extract_document_segments(data, "student.xlsx")
    assert any("學生個資總表" in s.source for s in segments)
