"""台灣電話號碼偵測。"""
from __future__ import annotations

import re
from typing import Iterable

from .base import BaseDetector, Finding, Severity, mask_value


class TaiwanMobileDetector(BaseDetector):
    name = "taiwan_mobile"
    category = "phone"
    severity = Severity.HIGH
    # 09 開頭 8 位數字，允許 -、空白、+886 國碼
    pattern = re.compile(
        r"(?<![\d])(?:\+?886[-\s]?|0)9\d{2}[-\s]?\d{3}[-\s]?\d{3}(?![\d])"
    )

    def detect(self, text: str) -> Iterable[Finding]:
        for m in self.pattern.finditer(text):
            raw = m.group(0)
            digits = re.sub(r"\D", "", raw)
            # 規格化檢核：09 + 8 位
            if digits.startswith("886"):
                digits = "0" + digits[3:]
            if not re.fullmatch(r"09\d{8}", digits):
                continue
            yield self.make_finding(
                text,
                value=raw,
                start=m.start(),
                end=m.end(),
                masked=mask_value(digits, keep_head=4, keep_tail=2),
                notes="台灣行動電話",
            )


class TaiwanLandlineDetector(BaseDetector):
    name = "taiwan_landline"
    category = "phone"
    severity = Severity.MEDIUM
    # 0X-XXXXXXX, (0X)XXXXXXX, 區碼 02/03/04/05/06/07/08/037/049/082/089
    pattern = re.compile(
        r"(?<![\d])(?:\(0\d{1,2}\)|0\d{1,2})[-\s]?\d{6,8}(?![\d])"
    )

    def detect(self, text: str) -> Iterable[Finding]:
        for m in self.pattern.finditer(text):
            raw = m.group(0)
            digits = re.sub(r"\D", "", raw)
            if not (8 <= len(digits) <= 10) or not digits.startswith("0"):
                continue
            # 排除手機 09 開頭
            if digits.startswith("09"):
                continue
            yield self.make_finding(
                text,
                value=raw,
                start=m.start(),
                end=m.end(),
                masked=mask_value(digits, keep_head=2, keep_tail=2),
                notes="台灣市話",
            )
