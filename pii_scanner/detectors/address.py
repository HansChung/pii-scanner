"""台灣地址偵測 (使用啟發式關鍵字)。"""
from __future__ import annotations

import re
from typing import Iterable

from .base import BaseDetector, Finding, Severity

# 縣市 + 鄉鎮市區 + ...路/街/巷/弄/號
ADDRESS_PATTERN = re.compile(
    r"(?:台灣|臺灣)?"  # 國名 (可選)
    r"(?:[\u4e00-\u9fa5]{2,4}(?:市|縣))"  # 縣市
    r"(?:[\u4e00-\u9fa5]{1,5}(?:區|鄉|鎮|市))?"  # 鄉鎮市區
    r"(?:[\u4e00-\u9fa5\d]{1,8}(?:路|街|大道))"  # 路/街/大道
    r"(?:[\u4e00-\u9fa5\d]{1,5}段)?"
    r"(?:\d+巷)?"
    r"(?:\d+弄)?"
    r"\d+號"
    r"(?:之\d+)?"
    r"(?:\d+樓)?"
    r"(?:之\d+)?"
)


class TaiwanAddressDetector:
    name = "taiwan_address"
    category = "address"
    severity = Severity.MEDIUM

    def detect(self, text: str) -> Iterable:
        from .base import Finding, build_context

        for m in ADDRESS_PATTERN.finditer(text):
            value = m.group(0)
            yield Finding(
                detector=self.name,
                category=self.category,
                severity=self.severity,
                value=value,
                masked=value[:4] + "****",
                start=m.start(),
                end=m.end(),
                context=build_context(text, m.start(), m.end()),
                notes="台灣地址 (啟發式)",
            )
