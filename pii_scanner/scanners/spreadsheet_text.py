"""試算表列 → 掃描用文字（保留表頭語意；無表頭時補姓名脈絡）。"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Sequence

from ..detectors.surname_data import COMPOUND_SURNAMES, SINGLE_SURNAMES, NAME_STOPWORDS

# 判斷某列是否為表頭
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

# 表頭儲存格不會出現號碼或 Email；出現就是資料列或表單列
_VALUE_LIKE = re.compile(r"\d{3,}|@")

# 表頭可能不在第一列（常見：第一列是標題），往下找幾列
_HEADER_SEARCH_ROWS = 5

# 姓名類欄位的其他常見寫法（只用於替欄位值加上「姓名：」，不用來判斷表頭）
_NAME_LIKE_HEADERS = {"申請人", "監護人", "家長", "得獎者", "受獎人", "受獎學生", "得獎學生"}

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


def _is_name_like_header(header: str) -> bool:
    h = header.strip()
    if _is_name_column_header(h):
        return True
    return h in _NAME_LIKE_HEADERS or ("姓名" in h and len(h) <= 8)


def _is_label_cell(cell: str) -> bool:
    return bool(_HEADER_HINT.search(cell)) or _is_name_column_header(cell)


def _is_label_value_pairs(cells: Sequence[str]) -> bool:
    """表單式列「欄名、值、欄名、值」（如 姓名｜王小明｜性別｜男）不是表頭。"""
    if len(cells) % 2:
        return False
    labels, values = cells[0::2], cells[1::2]
    return all(_is_label_cell(c) for c in labels) and not any(_is_label_cell(c) for c in values)


def _looks_like_header_row(cells: Sequence[str]) -> bool:
    non_empty = [c for c in cells if c]
    if len(non_empty) < 2:
        return False
    if any(_VALUE_LIKE.search(c) for c in non_empty) or _is_label_value_pairs(non_empty):
        return False
    hits = sum(1 for c in non_empty if _HEADER_HINT.search(c))
    if hits >= 2:
        return True
    return any(_is_name_column_header(c) for c in non_empty)


def _format_cell(header: str, value: str, *, has_header_row: bool) -> str:
    if not value:
        return ""
    if has_header_row and header and _is_name_like_header(header):
        return f"姓名：{value}"
    if not has_header_row and looks_like_person_name(value):
        return f"姓名：{value}"
    if has_header_row and header:
        return f"{header}：{value}"
    return value


@dataclass(frozen=True)
class LabeledRow:
    """一列轉成的掃描文字；row_number 為原始列號（1 起算，含空白列）。"""

    row_number: int
    text: str
    is_header: bool = False


def labeled_rows(
    rows: Iterable[Iterable[object]], *, max_rows: int | None = None
) -> list[LabeledRow]:
    """逐列轉成帶欄位語意的文字。

    找到表頭後，其下每一格都寫成「欄名：值」（姓名欄統一為「姓名：值」），
    讓需要關鍵字的規則（學號、姓名、生日、帳號…）在表格裡也抓得到；
    各格以 tab 分隔，避免相鄰儲存格的數字被串成一個號碼。
    表頭列本身原樣輸出（is_header=True）；表頭之前的列（如標題）與無表頭時依原規則補姓名脈絡。
    """
    materialized: list[tuple[int, list[str]]] = []
    for row_number, row in enumerate(rows, start=1):
        if max_rows is not None and len(materialized) >= max_rows:
            materialized.append((row_number, ["…(已達列數上限)"]))
            break
        cells = [cell_str(c) for c in row]
        if any(cells):
            materialized.append((row_number, cells))

    header_index = next(
        (
            index
            for index, (_, cells) in enumerate(materialized[:_HEADER_SEARCH_ROWS])
            if _looks_like_header_row(cells)
        ),
        None,
    )
    headers: list[str] = materialized[header_index][1] if header_index is not None else []

    result: list[LabeledRow] = []
    for index, (row_number, cells) in enumerate(materialized):
        if index == header_index:
            result.append(LabeledRow(row_number, "\t".join(headers), is_header=True))
            continue
        labeled = header_index is not None and index > header_index
        row_headers = headers if labeled else []
        parts: list[str] = []
        for i in range(max(len(cells), len(row_headers))):
            header = row_headers[i] if i < len(row_headers) else ""
            value = cells[i] if i < len(cells) else ""
            if not labeled and i > 0 and _is_name_column_header(cells[i - 1]):
                # 表單式「姓名｜王小明」：前一格已是欄名，不再補「姓名：」
                formatted = value
            else:
                formatted = _format_cell(header, value, has_header_row=labeled)
            if formatted:
                parts.append(formatted)
        if parts:
            result.append(LabeledRow(row_number, "\t".join(parts)))
    return result


def rows_to_scan_text(rows: Iterable[Iterable[object]], *, max_rows: int) -> str:
    """將試算表列轉為帶欄位語意的文字，供規則式 / Azure AI 掃描。"""
    return "\n".join(row.text for row in labeled_rows(rows, max_rows=max_rows))
