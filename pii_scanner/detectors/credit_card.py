"""信用卡號偵測：Luhn 演算法驗證。"""
from __future__ import annotations

import re
from typing import Iterable

from .base import BaseDetector, Finding, Severity, mask_value


def luhn_check(card_number: str) -> bool:
    digits = [int(c) for c in card_number if c.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


class CreditCardDetector(BaseDetector):
    name = "credit_card"
    category = "financial"
    severity = Severity.CRITICAL
    pattern = re.compile(
        r"(?<![\d])(?:\d[ -]?){12,18}\d(?![\d])"
    )

    def detect(self, text: str) -> Iterable[Finding]:
        for m in self.pattern.finditer(text):
            raw = m.group(0)
            digits = re.sub(r"\D", "", raw)
            if not (13 <= len(digits) <= 19):
                continue
            if not luhn_check(digits):
                continue
            yield self.make_finding(
                text,
                value=raw,
                start=m.start(),
                end=m.end(),
                masked=mask_value(digits, keep_head=4, keep_tail=4),
                notes=f"通過 Luhn 校驗，可能為信用卡號 ({len(digits)} 位)",
            )
