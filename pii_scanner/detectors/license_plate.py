"""台灣車牌號碼偵測 (新式: AAA-1234 / ABC-1234 / 1234-AB 等)。"""
from __future__ import annotations

import re
from typing import Iterable

from .base import BaseDetector, Finding, Severity


class TaiwanLicensePlateDetector(BaseDetector):
    name = "taiwan_license_plate"
    category = "vehicle"
    severity = Severity.LOW
    patterns = [
        re.compile(r"(?<![A-Za-z0-9])[A-Z]{3}-\d{4}(?![A-Za-z0-9])"),       # ABC-1234
        re.compile(r"(?<![A-Za-z0-9])[A-Z]{2}-\d{4}(?![A-Za-z0-9])"),       # AB-1234
        re.compile(r"(?<![A-Za-z0-9])\d{4}-[A-Z]{2}(?![A-Za-z0-9])"),       # 1234-AB
        re.compile(r"(?<![A-Za-z0-9])\d{3}-[A-Z]{3}(?![A-Za-z0-9])"),       # 123-ABC
    ]

    def detect(self, text: str) -> Iterable[Finding]:
        for pat in self.patterns:
            for m in pat.finditer(text):
                value = m.group(0)
                yield self.make_finding(
                    text,
                    value=value,
                    start=m.start(),
                    end=m.end(),
                    masked=value[:2] + "****",
                    notes="台灣車牌號碼",
                )
