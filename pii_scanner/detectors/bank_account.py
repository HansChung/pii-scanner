"""銀行帳號偵測 (10-16 位連續數字，需關鍵字輔助)。"""
from __future__ import annotations

import re
from typing import Iterable

from .base import BaseDetector, Finding, Severity, mask_value


class BankAccountDetector(BaseDetector):
    name = "bank_account"
    category = "financial"
    severity = Severity.HIGH
    pattern = re.compile(
        r"(?:帳[號戶](?:號碼)?|Bank\s*Account|A/C(?:\s*No\.?)?)[\s:：#＃]*([\d\-\s]{10,22})",
        re.IGNORECASE,
    )

    def detect(self, text: str) -> Iterable[Finding]:
        for m in self.pattern.finditer(text):
            raw = m.group(1).strip()
            digits = re.sub(r"\D", "", raw)
            if not (10 <= len(digits) <= 16):
                continue
            yield self.make_finding(
                text,
                value=raw,
                start=m.start(1),
                end=m.end(1),
                masked=mask_value(digits, keep_head=2, keep_tail=4),
                notes=f"可能為銀行帳號 ({len(digits)} 位)",
            )
