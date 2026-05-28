"""網頁頁尾/維護資訊中的中文姓名偵測。

針對大學、政府網站常見格式，比全文百家姓掃描精準：
  - 資料維護：秘書處 江雅玲
  - 網頁建置：資訊處 張秀榕
  - 承辦人：王小明
"""
from __future__ import annotations

import re
from typing import Iterable, Optional, Tuple

from .base import BaseDetector, Finding, Severity, mask_value
from .surname_data import COMPOUND_SURNAMES, SINGLE_SURNAMES

# 常見單位/處室（頁尾維護人員前綴）
DEPARTMENTS = (
    r"秘書處|資訊處|資訊中心|資訊組|電算中心|計算機中心|計中|"
    r"人事室|人事處|總務處|學務處|教務處|體育處|學生事務處|"
    r"圖書館|公共事務組|文書組|出納組|主計室|主計處"
)

# 維護標籤
MAINTAINER_LABELS = (
    r"資料維護|網頁建置|網站建置|網站維護|網頁維護|內容維護|"
    r"網頁管理|網站管理|頁面維護|資訊維護|更新日期"
)

# 職稱/角色標籤（直接接姓名）
ROLE_LABELS = (
    r"承辦人|聯絡人|維護人員|資料維護人|網站管理員|"
    r"撰稿|編輯|設計|製表"
)

_COMPOUND_SORTED = tuple(sorted(COMPOUND_SURNAMES, key=len, reverse=True))


def _starts_with_surname(name: str) -> bool:
    if len(name) < 2 or len(name) > 4:
        return False
    for sur in _COMPOUND_SORTED:
        if name.startswith(sur):
            return True
    return name[0] in SINGLE_SURNAMES


def _looks_like_person_name(name: str) -> bool:
    """排除處室名稱誤判（如「秘書處」「資訊處」本身）。"""
    if not _starts_with_surname(name):
        return False
    # 結尾為「處/組/室/科/課/中心/館」多半是單位名
    if name[-1] in "處組室科課館心":
        return False
    if name in {"資訊處", "秘書處", "總務處", "學務處", "教務處", "人事室", "主計室"}:
        return False
    return True


class ContextNameDetector(BaseDetector):
    """依頁尾/維護上下文偵測中文姓名（含百家姓驗證）。"""

    name = "context_name"
    category = "name"
    severity = Severity.LOW

    patterns = [
        # 資料維護：秘書處 江雅玲 / 網頁建置：資訊處 張秀榕
        re.compile(
            rf"(?:{MAINTAINER_LABELS})[：:\s]*"
            rf"(?:(?:{DEPARTMENTS})[\s　]*)?"
            rf"([\u4e00-\u9fa5]{{2,4}})(?![\u4e00-\u9fa5])"
        ),
        # 秘書處 江雅玲（單獨出現）
        re.compile(
            rf"(?:{DEPARTMENTS})[\s　]+"
            rf"([\u4e00-\u9fa5]{{2,4}})(?![\u4e00-\u9fa5])"
        ),
        # 承辦人：王小明
        re.compile(
            rf"(?:{ROLE_LABELS})[：:\s]+"
            rf"([\u4e00-\u9fa5]{{2,4}})(?![\u4e00-\u9fa5])"
        ),
    ]

    def detect(self, text: str) -> Iterable[Finding]:
        seen: set[Tuple[int, int]] = set()
        for pat in self.patterns:
            for m in pat.finditer(text):
                value = m.group(1)
                if not _looks_like_person_name(value):
                    continue
                span = (m.start(1), m.end(1))
                if span in seen:
                    continue
                seen.add(span)
                yield self.make_finding(
                    text,
                    value=value,
                    start=m.start(1),
                    end=m.end(1),
                    masked=mask_value(value, keep_head=1, keep_tail=0),
                    notes="可能為中文姓名 (頁尾/維護/單位上下文 + 百家姓)",
                )
