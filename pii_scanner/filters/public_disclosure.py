"""依法須公開的聯絡/維護資訊 — 姓名不視為個資。

政府、大學網站頁尾常見格式（依資訊公開或聯絡責任要求）：
  - 資料維護：秘書處 江雅玲
  - 網頁建置：資訊處 張秀榕
  - 承辦人：王小明
"""
from __future__ import annotations

import re
from typing import List

from ..detectors.base import Finding

# 常見單位/處室（頁尾維護人員前綴）
_DEPARTMENTS = (
    r"秘書處|資訊處|資訊中心|資訊組|電算中心|計算機中心|計中|"
    r"人事室|人事處|總務處|學務處|教務處|體育處|學生事務處|"
    r"圖書館|公共事務組|文書組|出納組|主計室|主計處"
)

# 維護標籤
_MAINTAINER_LABELS = (
    r"資料維護|網頁建置|網站建置|網站維護|網頁維護|內容維護|"
    r"網頁管理|網站管理|頁面維護|資訊維護"
)

# 職稱/角色（頁面依法公開之聯絡窗口）
_ROLE_LABELS = (
    r"承辦人|聯絡人|維護人員|資料維護人|網站管理員"
)

# 姓名前脈絡：標籤 + 可選處室，緊接姓名
_PUBLIC_NAME_BEFORE = re.compile(
    rf"(?:{_MAINTAINER_LABELS})[：:\s]*"
    rf"(?:(?:{_DEPARTMENTS})[\s　]*)?"
    rf"$"
)

# 處室 + 姓名
_DEPT_NAME_BEFORE = re.compile(
    rf"(?:{_DEPARTMENTS})[\s　]+$"
)

# 承辦人/聯絡人等 + 姓名
_ROLE_NAME_BEFORE = re.compile(
    rf"(?:{_ROLE_LABELS})[：:\s]+$"
)


def is_public_disclosure_name(text: str, start: int, end: int) -> bool:
    """判斷該姓名是否位於依法須公開的維護/承辦脈絡。"""
    if start < 0 or end > len(text) or start >= end:
        return False
    # 向前檢視足夠脈絡（頁尾一行通常 < 60 字）
    lo = max(0, start - 64)
    before = text[lo:start]
    return bool(
        _PUBLIC_NAME_BEFORE.search(before)
        or _DEPT_NAME_BEFORE.search(before)
        or _ROLE_NAME_BEFORE.search(before)
    )


def exclude_public_disclosure_names(text: str, findings: List[Finding]) -> List[Finding]:
    """過濾掉依法公開聯絡脈絡中的姓名命中。"""
    out: List[Finding] = []
    for f in findings:
        if f.category == "name" and is_public_disclosure_name(text, f.start, f.end):
            continue
        out.append(f)
    return out
