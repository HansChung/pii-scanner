"""PII 偵測器集合。

每個偵測器需要繼承 :class:`BaseDetector`，並實作 :py:meth:`detect`。
本模組同時提供 :func:`detect_in_text`，會跑過所有已註冊的偵測器並回傳結果。
"""
from __future__ import annotations

from typing import Iterable, List

from .base import BaseDetector, Finding, Severity
from .taiwan_id import TaiwanIDDetector, TaiwanResidentCertDetector
from .phone import TaiwanMobileDetector, TaiwanLandlineDetector
from .email import EmailDetector
from .credit_card import CreditCardDetector
from .tax_id import TaiwanBusinessIDDetector
from .passport import TaiwanPassportDetector
from .nhi_card import TaiwanNHICardDetector
from .license_plate import TaiwanLicensePlateDetector
from .ip_address import IPv4Detector, IPv6Detector
from .bank_account import BankAccountDetector
from .date_of_birth import DateOfBirthDetector
from .address import TaiwanAddressDetector
from .name import ChineseNameDetector
from .surname_name import SurnameNameDetector, SurnameMatchMode, find_surname_names

_CORE_DETECTORS: List[BaseDetector] = [
    TaiwanIDDetector(),
    TaiwanResidentCertDetector(),
    TaiwanMobileDetector(),
    TaiwanLandlineDetector(),
    EmailDetector(),
    CreditCardDetector(),
    TaiwanBusinessIDDetector(),
    TaiwanPassportDetector(),
    TaiwanNHICardDetector(),
    TaiwanLicensePlateDetector(),
    IPv4Detector(),
    IPv6Detector(),
    BankAccountDetector(),
    DateOfBirthDetector(),
    TaiwanAddressDetector(),
    ChineseNameDetector(),  # 關鍵字版姓名（姓名：XXX）
]

_OPTIONAL_DETECTORS: List[BaseDetector] = [
    SurnameNameDetector(),  # 百家姓全文；預設關閉，誤判率高
]


def get_active_detectors(*, include_surname: bool | None = None) -> List[BaseDetector]:
    """回傳目前應啟用的偵測器清單。"""
    from ..settings import ENABLE_SURNAME_NAME

    use_surname = ENABLE_SURNAME_NAME if include_surname is None else include_surname
    dets = list(_CORE_DETECTORS)
    if use_surname:
        dets.extend(_OPTIONAL_DETECTORS)
    return dets


ALL_DETECTORS: List[BaseDetector] = get_active_detectors()


def _dedupe_findings(findings: List[Finding]) -> List[Finding]:
    """合併同一位置、同類別的重複命中（如 chinese_name 與 surname_name）。"""
    best: dict[tuple, Finding] = {}
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for f in findings:
        key = (f.start, f.end, f.category)
        prev = best.get(key)
        if prev is None:
            best[key] = f
            continue
        # 保留 severity 較高者；同級保留較短 detector 名（較具體）
        if severity_rank.get(f.severity.value, 9) < severity_rank.get(prev.severity.value, 9):
            best[key] = f
        elif f.severity == prev.severity and len(f.detector) < len(prev.detector):
            best[key] = f
    return sorted(best.values(), key=lambda x: (x.start, x.detector))


def detect_in_text(
    text: str,
    detectors: Iterable[BaseDetector] | None = None,
    source: str | None = None,
) -> List[Finding]:
    """跑過所有 (或指定) 偵測器，回傳 :class:`Finding` 清單。"""
    if detectors is None:
        detectors = get_active_detectors()
    findings: List[Finding] = []
    for det in detectors:
        for f in det.detect(text):
            if source is not None:
                f.source = source
            findings.append(f)
    findings = _dedupe_findings(findings)
    return findings


__all__ = [
    "ALL_DETECTORS",
    "get_active_detectors",
    "BaseDetector",
    "Finding",
    "Severity",
    "SurnameMatchMode",
    "SurnameNameDetector",
    "find_surname_names",
    "detect_in_text",
]
