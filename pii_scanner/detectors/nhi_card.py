"""健保卡號偵測 (12 位數字，通常需關鍵字輔助)。"""
from __future__ import annotations

import re
from typing import Iterable

from .base import BaseDetector, Finding, Severity, mask_value


class TaiwanNHICardDetector(BaseDetector):
    name = "taiwan_nhi_card"
    category = "health"
    severity = Severity.HIGH
    pattern = re.compile(
        r"(?:健保卡(?:號碼|號)?|NHI(?:\s*Card)?)[\s:：#＃]*(\d{12})",
        re.IGNORECASE,
    )

    def detect(self, text: str) -> Iterable[Finding]:
        for m in self.pattern.finditer(text):
            value = m.group(1)
            yield self.make_finding(
                text,
                value=value,
                start=m.start(1),
                end=m.end(1),
                masked=mask_value(value, keep_head=4, keep_tail=2),
                notes="健保卡卡號 (依關鍵字)",
            )
