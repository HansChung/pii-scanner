"""偵測器基底類別與資料結構。"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Iterable, List, Optional


class Severity(str, Enum):
    """嚴重程度分級。

    - ``CRITICAL``：高敏感個資，外洩會造成立即傷害（如身分證號、信用卡）。
    - ``HIGH``：強識別性個資（如手機、護照）。
    - ``MEDIUM``：間接識別個資（如 Email、IP）。
    - ``LOW``：可能個資但誤判機率較高（如疑似姓名、地址片段）。
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Finding:
    """單筆 PII 命中紀錄。"""

    detector: str
    category: str
    severity: Severity
    value: str
    masked: str
    start: int
    end: int
    context: str = ""
    source: Optional[str] = None
    notes: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


def mask_value(value: str, keep_head: int = 1, keep_tail: int = 1, mask_char: str = "*") -> str:
    """將字串中間段以星號取代以利顯示。"""
    if not value:
        return value
    if len(value) <= keep_head + keep_tail:
        return mask_char * len(value)
    head = value[:keep_head]
    tail = value[-keep_tail:] if keep_tail > 0 else ""
    return f"{head}{mask_char * (len(value) - keep_head - keep_tail)}{tail}"


def build_context(text: str, start: int, end: int, window: int = 24) -> str:
    """擷取命中前後的上下文字串以便人工複核。"""
    lo = max(0, start - window)
    hi = min(len(text), end + window)
    prefix = "…" if lo > 0 else ""
    suffix = "…" if hi < len(text) else ""
    snippet = text[lo:hi].replace("\n", " ").replace("\r", " ")
    return f"{prefix}{snippet}{suffix}"


class BaseDetector:
    """所有偵測器需繼承的基底類別。

    子類別必須實作 :py:meth:`detect`，可選擇覆寫 :py:meth:`validate` 提供額外驗證。
    """

    name: str = "base"
    category: str = "generic"
    severity: Severity = Severity.MEDIUM

    def detect(self, text: str) -> Iterable[Finding]:  # pragma: no cover - 抽象
        raise NotImplementedError

    def validate(self, value: str) -> bool:  # pragma: no cover - 預設不額外驗證
        return True

    def make_finding(
        self,
        text: str,
        value: str,
        start: int,
        end: int,
        masked: Optional[str] = None,
        notes: str = "",
    ) -> Finding:
        return Finding(
            detector=self.name,
            category=self.category,
            severity=self.severity,
            value=value,
            masked=masked if masked is not None else mask_value(value),
            start=start,
            end=end,
            context=build_context(text, start, end),
            notes=notes,
        )


def collect(detectors: Iterable[BaseDetector], text: str) -> List[Finding]:
    """跑多個偵測器並合併結果。"""
    out: List[Finding] = []
    for det in detectors:
        out.extend(det.detect(text))
    return out
