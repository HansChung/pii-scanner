"""文字掃描器：對給定字串執行所有偵測器。"""
from __future__ import annotations

from typing import Dict, Iterable, List, Optional

from ..detectors import detect_in_text
from ..detectors.base import BaseDetector, Finding


def scan_text(
    text: str,
    *,
    source: Optional[str] = None,
    detectors: Optional[Iterable[BaseDetector]] = None,
    preview: Optional[Dict[str, str]] = None,
) -> List[Finding]:
    """掃描單一字串，回傳所有命中。若傳入 *preview* 字典，會記錄原文以供高亮預覽。"""
    findings = detect_in_text(text, detectors=detectors, source=source)
    if preview is not None and text:
        preview[source or "<inline>"] = text
    return findings
