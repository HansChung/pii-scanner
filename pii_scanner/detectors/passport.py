"""台灣護照號碼偵測 (9 位數字，第 1 位多為 1-3)。

需仰賴上下文 (如 "護照"/"passport") 以降低誤判。
"""
from __future__ import annotations

import re
from typing import Iterable

from .base import BaseDetector, Finding, Severity, mask_value


class TaiwanPassportDetector(BaseDetector):
    name = "taiwan_passport"
    category = "passport"
    severity = Severity.HIGH
    # 護照: 9 位數字，需有關鍵字輔助判斷
    pattern = re.compile(
        r"(?:護照(?:號碼|號)?|Passport(?:\s*(?:No\.?|Number))?|PP)[\s:：#＃]*([0-3]\d{8})",
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
                masked=mask_value(value, keep_head=2, keep_tail=2),
                notes="可能為台灣護照號碼 (依關鍵字)",
            )
