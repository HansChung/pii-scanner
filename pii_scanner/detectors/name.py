"""中文姓名偵測 (依關鍵字輔助)。

避免直接掃描 2-3 字中文，誤判極高。改採「姓名：XXX」「敬啟者 XXX」等上下文。
"""
from __future__ import annotations

import re
from typing import Iterable

from .base import BaseDetector, Finding, Severity

KEYWORDS = (
    r"(?:姓\s*名|本人|申請人|聯絡人|收件人|寄件人|當事人|"
    r"Name|Full\s*Name|Contact(?:\s*Person)?)"
)

# 試算表標題列常見欄位名，避免「姓名\t出生日期」誤判為姓名
_HEADER_LIKE = re.compile(
    r"日期|地址|電話|郵箱|信箱|卡號|帳號|備註|收入|性別|血型|編號|單位|科系|名稱|英文"
)


class ChineseNameDetector(BaseDetector):
    name = "chinese_name"
    category = "name"
    severity = Severity.LOW
    pattern = re.compile(
        KEYWORDS + r"[\s:：]*([\u4e00-\u9fa5]{2,4})(?![\u4e00-\u9fa5])",
        re.IGNORECASE,
    )

    def detect(self, text: str) -> Iterable[Finding]:
        for m in self.pattern.finditer(text):
            value = m.group(1)
            if _HEADER_LIKE.search(value) or value in {"同戶籍", "同戶籍地址"}:
                continue
            yield self.make_finding(
                text,
                value=value,
                start=m.start(1),
                end=m.end(1),
                masked=value[0] + "*" * (len(value) - 1),
                notes="可能為中文姓名 (依關鍵字)",
            )
