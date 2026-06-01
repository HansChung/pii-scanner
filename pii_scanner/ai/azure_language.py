"""Azure AI Language — 可選 PII 增強分析（依使用者勾選才呼叫 API）。"""
from __future__ import annotations

from typing import List, Optional, Tuple

from ..detectors.base import Finding, Severity, build_context, mask_value
from ..settings import (
    AZURE_LANGUAGE_ENDPOINT,
    AZURE_LANGUAGE_KEY,
    AI_MAX_CHARS,
)

# Azure PII 類別 → (本系統 category, severity)
_AZURE_PII_MAP: dict[str, Tuple[str, Severity]] = {
    "Person": ("name", Severity.LOW),
    "PersonType": ("name", Severity.LOW),
    "PhoneNumber": ("phone", Severity.HIGH),
    "Email": ("email", Severity.MEDIUM),
    "Address": ("address", Severity.LOW),
    "Date": ("date", Severity.LOW),
    "Age": ("date", Severity.LOW),
    "Organization": ("organization", Severity.LOW),
    "URL": ("url", Severity.LOW),
    "IPAddress": ("ip", Severity.MEDIUM),
    "CreditCardNumber": ("financial", Severity.CRITICAL),
    "ABARoutingNumber": ("financial", Severity.HIGH),
    "InternationalBankingAccountNumber": ("financial", Severity.HIGH),
    "USSocialSecurityNumber": ("id", Severity.CRITICAL),
    "USDriversLicenseNumber": ("id", Severity.HIGH),
    "USPassportNumber": ("id", Severity.HIGH),
    "TWNationalID": ("id", Severity.CRITICAL),
    "TWNationalIDNumber": ("id", Severity.CRITICAL),
}


class AzurePiiError(Exception):
    """Azure AI 呼叫失敗。"""


def is_ai_configured() -> bool:
    return bool(AZURE_LANGUAGE_ENDPOINT and AZURE_LANGUAGE_KEY)


def _map_entity(category: str) -> Tuple[str, Severity]:
    return _AZURE_PII_MAP.get(category, ("generic", Severity.MEDIUM))


def _entity_to_finding(text: str, entity, source: Optional[str]) -> Finding:
    cat, severity = _map_entity(entity.category)
    start = entity.offset
    end = entity.offset + entity.length
    value = entity.text
    sub = getattr(entity, "subcategory", None) or ""
    conf = getattr(entity, "confidence_score", None)
    conf_note = f"，信心 {conf:.0%}" if conf is not None else ""
    notes = f"Azure AI PII ({entity.category}{('/' + sub) if sub else ''}{conf_note})"
    return Finding(
        detector="azure_ai_pii",
        category=cat,
        severity=severity,
        value=value,
        masked=mask_value(value, keep_head=1, keep_tail=1 if len(value) > 2 else 0),
        start=start,
        end=end,
        context=build_context(text, start, end),
        source=source,
        notes=notes,
    )


def detect_pii_with_azure(text: str, *, source: Optional[str] = None) -> Tuple[List[Finding], int]:
    """呼叫 Azure Language recognize_pii_entities；回傳 (findings, 分析字元數)。"""
    if not is_ai_configured():
        raise AzurePiiError("未設定 AZURE_LANGUAGE_ENDPOINT / AZURE_LANGUAGE_KEY")

    snippet = text[:AI_MAX_CHARS]
    if not snippet.strip():
        return [], 0

    try:
        from azure.ai.textanalytics import TextAnalyticsClient
        from azure.core.credentials import AzureKeyCredential
    except ImportError as exc:
        raise AzurePiiError("缺少 azure-ai-textanalytics 套件") from exc

    client = TextAnalyticsClient(
        endpoint=AZURE_LANGUAGE_ENDPOINT,
        credential=AzureKeyCredential(AZURE_LANGUAGE_KEY),
    )

    try:
        # 繁中優先；Azure 亦會自動偵測語言
        response = client.recognize_pii_entities([snippet], language="zh-Hant")
    except TypeError:
        response = client.recognize_pii_entities([snippet])
    except Exception as exc:
        raise AzurePiiError(f"Azure AI 呼叫失敗：{exc}") from exc

    findings: List[Finding] = []
    for doc in response:
        if getattr(doc, "is_error", False):
            err = getattr(doc, "error", doc)
            raise AzurePiiError(f"Azure AI 文件錯誤：{err}")
        for entity in doc.entities:
            findings.append(_entity_to_finding(snippet, entity, source))
    return findings, len(snippet)


def merge_ai_findings(base: List[Finding], ai_findings: List[Finding]) -> List[Finding]:
    """合併規則式與 AI 命中，重疊位置同 category 去重。"""
    out = list(base)
    for af in ai_findings:
        overlap = False
        for bf in base:
            if bf.category != af.category:
                continue
            if af.start < bf.end and af.end > bf.start:
                overlap = True
                break
        if not overlap:
            out.append(af)
    return sorted(out, key=lambda f: (f.start, f.detector))
