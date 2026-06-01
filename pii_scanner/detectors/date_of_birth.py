"""生日 / 出生日期偵測 (需關鍵字輔助)。"""
from __future__ import annotations

import re
from typing import Iterable

from .base import BaseDetector, Finding, Severity


class DateOfBirthDetector(BaseDetector):
    name = "date_of_birth"
    category = "demographic"
    severity = Severity.MEDIUM
    pattern = re.compile(
        r"(?:生日|出生(?:日期|年月日)?|DOB|Birth(?:day|date)?)"
        r"[\s:：]*"
        r"(\d{2,4}[-/年.]\s?\d{1,2}[-/月.]\s?\d{1,2}日?)",
        re.IGNORECASE,
    )

    def detect(self, text: str) -> Iterable[Finding]:
        for m in self.pattern.finditer(text):
            value = m.group(1).strip()
            yield self.make_finding(
                text,
                value=value,
                start=m.start(1),
                end=m.end(1),
                masked="****-**-**",
                notes="出生日期",
            )
