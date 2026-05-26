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

ALL_DETECTORS: List[BaseDetector] = [
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
    ChineseNameDetector(),
]


def detect_in_text(
    text: str,
    detectors: Iterable[BaseDetector] | None = None,
    source: str | None = None,
) -> List[Finding]:
    """跑過所有 (或指定) 偵測器，回傳 :class:`Finding` 清單。"""
    if detectors is None:
        detectors = ALL_DETECTORS
    findings: List[Finding] = []
    for det in detectors:
        for f in det.detect(text):
            if source is not None:
                f.source = source
            findings.append(f)
    findings.sort(key=lambda f: (f.start, f.detector))
    return findings


__all__ = [
    "ALL_DETECTORS",
    "BaseDetector",
    "Finding",
    "Severity",
    "detect_in_text",
]
