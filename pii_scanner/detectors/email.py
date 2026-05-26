"""Email 偵測器。"""
from __future__ import annotations

import re
from typing import Iterable

from .base import BaseDetector, Finding, Severity, mask_value


class EmailDetector(BaseDetector):
    name = "email"
    category = "email"
    severity = Severity.MEDIUM
    pattern = re.compile(
        r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
    )

    def detect(self, text: str) -> Iterable[Finding]:
        for m in self.pattern.finditer(text):
            value = m.group(0)
            local, _, domain = value.partition("@")
            if not local or not domain:
                continue
            masked_local = mask_value(local, keep_head=1, keep_tail=1)
            yield self.make_finding(
                text,
                value=value,
                start=m.start(),
                end=m.end(),
                masked=f"{masked_local}@{domain}",
                notes="電子郵件地址",
            )
