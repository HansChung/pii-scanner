"""掃描結果合併 Azure AI 增強（可選）。"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from ..detectors.base import Finding
from ..filters import exclude_public_disclosure_names
from ..settings import EXCLUDE_PUBLIC_DISCLOSURE
from .azure_language import AzurePiiError, detect_pii_with_azure, is_ai_configured, merge_ai_findings


@dataclass
class ScanMeta:
    ai_requested: bool = False
    ai_used: bool = False
    ai_chars_analyzed: int = 0
    ai_warning: Optional[str] = None
    scanned_file: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "ai_requested": self.ai_requested,
            "ai_used": self.ai_used,
            "ai_chars_analyzed": self.ai_chars_analyzed,
            "ai_warning": self.ai_warning,
            "scanned_file": self.scanned_file,
        }


def maybe_enhance_with_ai(
    text: str,
    findings: List[Finding],
    *,
    source: Optional[str] = None,
    use_ai: bool = False,
) -> tuple[List[Finding], ScanMeta]:
    """若 use_ai 且已設定 Azure，合併 AI PII 結果。"""
    meta = ScanMeta(ai_requested=use_ai)
    if not use_ai:
        return findings, meta

    if not is_ai_configured():
        meta.ai_warning = "Azure AI 未設定（請在 App Service 設定 AZURE_LANGUAGE_ENDPOINT 與 AZURE_LANGUAGE_KEY）"
        return findings, meta

    if not text.strip():
        meta.ai_warning = "無可分析文字，略過 Azure AI"
        return findings, meta

    try:
        ai_findings, chars = detect_pii_with_azure(text, source=source)
        if EXCLUDE_PUBLIC_DISCLOSURE:
            ai_findings = exclude_public_disclosure_names(text, ai_findings)
        findings = merge_ai_findings(findings, ai_findings)
        meta.ai_used = True
        meta.ai_chars_analyzed = chars
    except AzurePiiError as exc:
        meta.ai_warning = str(exc)

    return findings, meta
