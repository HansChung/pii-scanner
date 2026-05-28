"""依檔案魔術位元組判斷 Office / 開放文件格式。"""
from __future__ import annotations

from io import BytesIO
from typing import Optional
from zipfile import ZipFile


def sniff_document_suffix(data: bytes) -> Optional[str]:
    """回傳偵測到的副檔名（含點），無法辨識則 None。"""
    if len(data) < 4:
        return None

    # PDF
    if data[:5] == b"%PDF-":
        return ".pdf"

    # 舊版 Excel 97-2003 (.xls)
    if data[:4] == b"\xd0\xcf\x11\xe0":
        return ".xls"

    # ZIP 容器：xlsx / docx / ods / odt
    if data[:4] == b"PK\x03\x04":
        try:
            with ZipFile(BytesIO(data)) as zf:
                names = set(zf.namelist())
                if any(n.startswith("xl/") for n in names):
                    return ".xlsx"
                if any(n.startswith("word/") for n in names):
                    return ".docx"
                if "mimetype" in names:
                    try:
                        mt = zf.read("mimetype").decode("utf-8", errors="ignore")
                    except Exception:
                        mt = ""
                    if "spreadsheet" in mt:
                        return ".ods"
                    if "text" in mt:
                        return ".odt"
                if "content.xml" in names and "meta.xml" in names:
                    return ".ods"
        except Exception:
            return None
    return None


def is_likely_binary(data: bytes) -> bool:
    """是否疑似二進位文件（不應以文字解碼後靜默掃描）。"""
    if sniff_document_suffix(data):
        return True
    sample = data[:4096]
    if not sample:
        return False
    if b"\x00" in sample:
        return True
    # 高比例不可列印字元
    non_print = sum(1 for b in sample if b < 9 or (13 < b < 32 and b not in (10, 13)))
    return non_print / len(sample) > 0.15
