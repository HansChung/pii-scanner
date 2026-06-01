from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ExtractedText:
    text: str
    location: str


@dataclass(frozen=True)
class Finding:
    detector: str
    category: str
    risk_level: str
    confidence: float
    masked_text: str
    location: str
    recommendation: str

