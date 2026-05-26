"""台灣統一編號 (公司營利事業) 偵測。

依財政部規則：8 位數字，加權 1,2,1,2,1,2,4,1，
總和 (含「7」位特殊處理) 可被 5 整除即合法。
"""
from __future__ import annotations

import re
from typing import Iterable

from .base import BaseDetector, Finding, Severity

WEIGHTS = [1, 2, 1, 2, 1, 2, 4, 1]


def validate_business_id(value: str) -> bool:
    if not re.fullmatch(r"\d{8}", value):
        return False
    digits = [int(c) for c in value]
    total = 0
    for d, w in zip(digits, WEIGHTS):
        prod = d * w
        total += prod // 10 + prod % 10
    if total % 5 == 0:
        return True
    # 第 7 位為 7 時，總和 +1 也算合法
    if digits[6] == 7 and (total + 1) % 5 == 0:
        return True
    return False


class TaiwanBusinessIDDetector(BaseDetector):
    name = "taiwan_business_id"
    category = "business_id"
    severity = Severity.MEDIUM
    pattern = re.compile(r"(?<!\d)\d{8}(?!\d)")

    def detect(self, text: str) -> Iterable[Finding]:
        for m in self.pattern.finditer(text):
            value = m.group(0)
            if validate_business_id(value):
                yield self.make_finding(
                    text,
                    value=value,
                    start=m.start(),
                    end=m.end(),
                    masked=value[:2] + "****" + value[-2:],
                    notes="台灣公司統一編號 (通過檢核)",
                )
