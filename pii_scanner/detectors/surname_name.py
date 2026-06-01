"""百家姓中文姓名偵測器。

以姓氏詞表 + 名字長度規則在全文掃描，並搭配排除詞、職稱/機構後綴過濾以降低誤判。
可選模式：

- ``strict``：僅在標點/空白邊界處比對，且排除常見誤判詞
- ``balanced``（預設）：全文掃描 + 排除詞 + 後綴過濾
- ``aggressive``：全文掃描，僅排除 stopwords，後綴過濾較寬鬆
"""
from __future__ import annotations

import re
from enum import Enum
from typing import Iterable, List, Optional, Set, Tuple

from .base import BaseDetector, Finding, Severity, mask_value
from .surname_data import (
    COMPOUND_SURNAMES,
    HONORIFIC_SUFFIXES,
    INSTITUTION_SUFFIXES,
    INVALID_GIVEN_CHARS,
    INVALID_GIVEN_PARTS,
    NAME_STOPWORDS,
    SINGLE_SURNAMES,
)

# 中文姓名用字（CJK Unified Ideographs 常用區）
_CJK = re.compile(r"[\u4e00-\u9fa5]")
# 邊界：前後不可緊接英數或另一個中文（strict 模式用）
_STRICT_BEFORE = re.compile(r"(?<![\u4e00-\u9fa5A-Za-z0-9])")
_STRICT_AFTER = re.compile(r"(?![\u4e00-\u9fa5A-Za-z0-9])")


class SurnameMatchMode(str, Enum):
    STRICT = "strict"
    BALANCED = "balanced"
    AGGRESSIVE = "aggressive"


def _sorted_compound_surnames() -> Tuple[str, ...]:
    return tuple(sorted(COMPOUND_SURNAMES, key=len, reverse=True))


def _match_surname(text: str, pos: int) -> Optional[Tuple[str, int]]:
    """自 ``pos`` 起嘗試比對姓氏，回傳 (姓氏, 姓氏字數) 或 None。"""
    if pos >= len(text) or not _CJK.match(text[pos]):
        return None
    for surname in _sorted_compound_surnames():
        if text.startswith(surname, pos):
            return surname, len(surname)
    ch = text[pos]
    if ch in SINGLE_SURNAMES:
        return ch, 1
    return None


def _given_name_len(surname_len: int, total_len: int) -> int:
    return total_len - surname_len


def _valid_name_lengths(surname_len: int, mode: SurnameMatchMode) -> range:
    """依姓氏長度決定允許的總姓名長度（由長到短嘗試）。"""
    if surname_len >= 2:
        lo, hi = 3, 4
    else:
        lo, hi = 2, 4 if mode == SurnameMatchMode.AGGRESSIVE else 3
    return range(hi, lo - 1, -1)


def _has_bad_suffix(text: str, end: int, mode: SurnameMatchMode) -> bool:
    """檢查姓名結尾後是否緊接職稱/機構後綴。"""
    rest = text[end:]
    suffixes = INSTITUTION_SUFFIXES
    if mode != SurnameMatchMode.AGGRESSIVE:
        suffixes = suffixes + HONORIFIC_SUFFIXES
    for suf in suffixes:
        if rest.startswith(suf):
            return True
    return False


def _is_boundary_ok(text: str, start: int, end: int, mode: SurnameMatchMode) -> bool:
    if mode != SurnameMatchMode.STRICT:
        return True
    before_ok = start == 0 or not (text[start - 1].isalnum() or _CJK.match(text[start - 1]))
    after_ok = end >= len(text) or not (text[end].isalnum() or _CJK.match(text[end]))
    return before_ok and after_ok


def find_surname_names(
    text: str,
    *,
    mode: SurnameMatchMode = SurnameMatchMode.BALANCED,
    extra_stopwords: Optional[Set[str]] = None,
) -> List[Tuple[str, int, int, str]]:
    """回傳 [(姓名, start, end, 姓氏), ...]。"""
    stopwords = NAME_STOPWORDS | (extra_stopwords or set())
    results: List[Tuple[str, int, int, str]] = []
    seen_spans: Set[Tuple[int, int]] = set()
    i = 0
    n = len(text)
    while i < n:
        if not _CJK.match(text[i]):
            i += 1
            continue
        matched = _match_surname(text, i)
        if not matched:
            i += 1
            continue
        surname, surname_len = matched
        found = False
        for total_len in _valid_name_lengths(surname_len, mode):
            end = i + total_len
            if end > n:
                continue
            segment = text[i:end]
            if not all(_CJK.match(c) for c in segment):
                continue
            if segment in stopwords:
                continue
            if _has_bad_suffix(text, end, mode):
                continue
            if not _is_boundary_ok(text, i, end, mode):
                continue
            given_len = _given_name_len(surname_len, total_len)
            if given_len < 1 or given_len > 2:
                if not (mode == SurnameMatchMode.AGGRESSIVE and given_len == 3 and surname_len == 1):
                    continue
            given_part = segment[surname_len:]
            if given_part in INVALID_GIVEN_PARTS:
                continue
            if any(c in INVALID_GIVEN_CHARS for c in given_part):
                continue
            if any(given_part.endswith(suf) for suf in INSTITUTION_SUFFIXES if len(suf) <= 2):
                continue
            span = (i, end)
            if span in seen_spans:
                continue
            seen_spans.add(span)
            results.append((segment, i, end, surname))
            found = True
            i = end  # 跳過已匹配區段，避免子字串重複命中
            break
        if not found:
            i += 1
    return results


class SurnameNameDetector(BaseDetector):
    """以百家姓詞表掃描中文姓名。"""

    name = "surname_name"
    category = "name"
    severity = Severity.LOW

    def __init__(
        self,
        mode: SurnameMatchMode | str = SurnameMatchMode.BALANCED,
        extra_stopwords: Optional[Set[str]] = None,
    ) -> None:
        if isinstance(mode, str):
            mode = SurnameMatchMode(mode)
        self.mode = mode
        self.extra_stopwords = extra_stopwords

    def detect(self, text: str) -> Iterable[Finding]:
        mode_notes = {
            SurnameMatchMode.STRICT: "strict：邊界 + 排除詞",
            SurnameMatchMode.BALANCED: "balanced：全文 + 排除詞 + 後綴過濾",
            SurnameMatchMode.AGGRESSIVE: "aggressive：全文 + 最少過濾",
        }
        for value, start, end, surname in find_surname_names(
            text, mode=self.mode, extra_stopwords=self.extra_stopwords
        ):
            yield self.make_finding(
                text,
                value=value,
                start=start,
                end=end,
                masked=mask_value(value, keep_head=1, keep_tail=0),
                notes=f"可能為中文姓名 (百家姓「{surname}」，{mode_notes[self.mode]})",
            )
