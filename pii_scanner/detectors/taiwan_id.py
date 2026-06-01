"""台灣身分證 / 居留證號偵測器。

身分證字號規則：
  - 1 個英文字母 + 9 位數字
  - 第二位為 1 (男) 或 2 (女)
  - 通過內政部公布的加權檢核

居留證 / 統一證號規則 (2021 後新版)：
  - 第一位英文 + 第二位英文 + 8 位數字
  - 第二位英文 (A=10, B=11 ... Z=35) 取個位數 + 偏移後做相同檢核
舊版居留證 (英文 + 數字 + 8 位數字, 第二位為 8 或 9) 也納入偵測。
"""
from __future__ import annotations

import re
from typing import Iterable

from .base import BaseDetector, Finding, Severity, mask_value

# 英文字母對應的兩位數
LETTER_VALUE = {
    "A": 10, "B": 11, "C": 12, "D": 13, "E": 14, "F": 15, "G": 16, "H": 17,
    "I": 34, "J": 18, "K": 19, "L": 20, "M": 21, "N": 22, "O": 35, "P": 23,
    "Q": 24, "R": 25, "S": 26, "T": 27, "U": 28, "V": 29, "W": 32, "X": 30,
    "Y": 31, "Z": 33,
}
WEIGHTS = [1, 9, 8, 7, 6, 5, 4, 3, 2, 1, 1]


def _checksum_id(numbers: list[int]) -> bool:
    total = sum(n * w for n, w in zip(numbers, WEIGHTS))
    return total % 10 == 0


def validate_taiwan_id(value: str) -> bool:
    value = value.upper()
    if not re.fullmatch(r"[A-Z][12]\d{8}", value):
        return False
    letter_val = LETTER_VALUE[value[0]]
    digits = [letter_val // 10, letter_val % 10] + [int(c) for c in value[1:]]
    return _checksum_id(digits)


def validate_resident_cert_new(value: str) -> bool:
    """新版統一證號（2 英文 + 8 數字）。"""
    value = value.upper()
    if not re.fullmatch(r"[A-Z][A-D]\d{8}", value):
        return False
    first = LETTER_VALUE[value[0]]
    second_letter = LETTER_VALUE[value[1]]
    second_digit = second_letter % 10
    digits = [first // 10, first % 10, second_digit] + [int(c) for c in value[2:]]
    return _checksum_id(digits)


def validate_resident_cert_old(value: str) -> bool:
    """舊版居留證 (1 英文 + 1 數字[89] + 8 數字)。"""
    value = value.upper()
    if not re.fullmatch(r"[A-Z][89]\d{8}", value):
        return False
    letter_val = LETTER_VALUE[value[0]]
    digits = [letter_val // 10, letter_val % 10] + [int(c) for c in value[1:]]
    return _checksum_id(digits)


class TaiwanIDDetector(BaseDetector):
    name = "taiwan_id"
    category = "national_id"
    severity = Severity.CRITICAL
    pattern = re.compile(r"(?<![A-Za-z0-9])[A-Za-z][12]\d{8}(?![A-Za-z0-9])")

    def detect(self, text: str) -> Iterable[Finding]:
        for m in self.pattern.finditer(text):
            value = m.group(0).upper()
            if validate_taiwan_id(value):
                yield self.make_finding(
                    text,
                    value=m.group(0),
                    start=m.start(),
                    end=m.end(),
                    masked=mask_value(value, keep_head=2, keep_tail=2),
                    notes="台灣身分證字號 (通過檢核碼)",
                )


class TaiwanResidentCertDetector(BaseDetector):
    name = "taiwan_resident_cert"
    category = "national_id"
    severity = Severity.CRITICAL
    pattern_new = re.compile(r"(?<![A-Za-z0-9])[A-Za-z][A-Da-d]\d{8}(?![A-Za-z0-9])")
    pattern_old = re.compile(r"(?<![A-Za-z0-9])[A-Za-z][89]\d{8}(?![A-Za-z0-9])")

    def detect(self, text: str) -> Iterable[Finding]:
        for m in self.pattern_new.finditer(text):
            value = m.group(0).upper()
            if validate_resident_cert_new(value):
                yield self.make_finding(
                    text,
                    value=m.group(0),
                    start=m.start(),
                    end=m.end(),
                    masked=mask_value(value, keep_head=2, keep_tail=2),
                    notes="新式統一證號 (居留證)",
                )
        for m in self.pattern_old.finditer(text):
            value = m.group(0).upper()
            if validate_resident_cert_old(value):
                yield self.make_finding(
                    text,
                    value=m.group(0),
                    start=m.start(),
                    end=m.end(),
                    masked=mask_value(value, keep_head=2, keep_tail=2),
                    notes="舊式居留證號",
                )
