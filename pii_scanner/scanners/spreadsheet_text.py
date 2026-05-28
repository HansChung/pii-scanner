"""試算表列 → 掃描用文字（保留表頭語意；無表頭時補姓名脈絡）。"""
from __future__ import annotations

import re
from typing import Iterable, List, Sequence

from ..detectors.surname_data import COMPOUND_SURNAMES, SINGLE_SURNAMES, NAME_STOPWORDS

# 判斷第一列是否為表頭
_HEADER_HINT = re.compile(
    r"姓名|名字|名稱|Name|手機|電話|Email|信箱|地址|出生|性別|學號|"
    r"帳號|卡號|備註|收入|血型|統編|部門|科系",
    re.IGNORECASE,
)

# 姓名欄表頭
_NAME_COLUMN = re.compile(
    r"^姓\s*名$|^名字$|^中文姓名$|^學生姓名$|^聯絡人姓名$|^Name$|^Full\s*Name$",
    re.IGNORECASE,
)

_COMPOUND_SORTED = tuple(sorted(COMPOUND_SURNAMES, key=len, reverse=True))

# 表頭列本身不當資料掃描
_HEADER_LIKE_VALUE = re.compile(
    r"日期|地址|電話|郵箱|信箱|卡號|帳號|備註|收入|性別|血型|編號|單位|科系|名稱|英文|手機|Email"
)


def cell_str(value: object) -> str:
    if value is None or value == "":
        return ""
    if isinstance(value, float):
        if value.is_integer():
            return str(int(value))
        return str(value).strip()
    return str(value).strip()


def _starts_with_surname(name: str) -> bool:
    if len(name) < 2 or len(name) > 4:
        return False
    for sur in _COMPOUND_SORTED:
        if name.startswith(sur):
            return True
    return name[0] in SINGLE_SURNAMES


def looks_like_person_name(name: str) -> bool:
    """試算表儲存格是否像中文姓名（百家姓 + 排除常見非人名）。"""
    name = name.strip()
    if not name or name in NAME_STOPWORDS or name in {"同戶籍", "同戶籍地址"}:
        return False
    if _HEADER_LIKE_VALUE.search(name):
        return False
    if not _starts_with_surname(name):
        return False
    if name[-1] in "處組室科課館心":
        return False
    return True


def _is_name_column_header(header: str) -> bool:
    h = header.strip()
    if not h:
        return False
    if _NAME_COLUMN.search(h):
        return True
    return h in {"姓名", "名字", "聯絡人", "緊急聯絡人", "學生姓名", "教師姓名"}


def _looks_like_header_row(cells: Sequence[str]) -> bool:
    non_empty = [c for c in cells if c]
    if len(non_empty) < 2:
        return False
    hits = sum(1 for c in non_empty if _HEADER_HINT.search(c))
    if hits >= 2:
        return True
    return any(_is_name_column_header(c) for c in non_empty)


def _format_cell(header: str, value: str, *, has_header_row: bool) -> str:
    if not value:
        return ""
    if has_header_row and header and _is_name_column_header(header):
        return f"姓名：{value}"
    if not has_header_row and looks_like_person_name(value):
        return f"姓名：{value}"
    if has_header_row and header:
        return f"{header}：{value}"
    return value


def rows_to_scan_text(rows: Iterable[Iterable[object]], *, max_rows: int) -> str:
    """將試算表列轉為帶欄位語意的文字，供規則式 / Azure AI 掃描。"""
    materialized: List[List[str]] = []
    count = 0
    for row in rows:
        if count >= max_rows:
            materialized.append(["…(已達列數上限)"])
            break
        cells = [cell_str(c) for c in row]
        if any(cells):
            materialized.append(cells)
            count += 1

    if not materialized:
        return ""

    has_header = _looks_like_header_row(materialized[0])
    headers: List[str] = materialized[0] if has_header else []
    data_rows = materialized[1:] if has_header else materialized

    lines: List[str] = []
    if has_header:
        lines.append("\t".join(headers))

    width = len(headers) if has_header else max((len(r) for r in data_rows), default=0)

    for row in data_rows:
        parts: List[str] = []
        for i in range(max(len(row), width)):
            header = headers[i] if has_header and i < len(headers) else ""
            value = row[i] if i < len(row) else ""
            formatted = _format_cell(header, value, has_header_row=has_header)
            if formatted:
                parts.append(formatted)
        if parts:
            lines.append("\t".join(parts))

    return "\n".join(lines)
