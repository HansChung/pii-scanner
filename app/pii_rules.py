from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Finding


@dataclass(frozen=True)
class Rule:
    category: str
    pattern: re.Pattern[str]
    risk_level: str
    recommendation: str


TAIWAN_ID_LETTER_VALUE = {
    "A": 10, "B": 11, "C": 12, "D": 13, "E": 14, "F": 15, "G": 16, "H": 17,
    "I": 34, "J": 18, "K": 19, "L": 20, "M": 21, "N": 22, "O": 35, "P": 23,
    "Q": 24, "R": 25, "S": 26, "T": 27, "U": 28, "V": 29, "W": 32, "X": 30,
    "Y": 31, "Z": 33,
}
TAIWAN_ID_WEIGHTS = [1, 9, 8, 7, 6, 5, 4, 3, 2, 1, 1]


def validate_taiwan_id(value: str) -> bool:
    value = value.upper()
    if not re.fullmatch(r"[A-Z][12]\d{8}", value):
        return False
    letter = TAIWAN_ID_LETTER_VALUE[value[0]]
    numbers = [letter // 10, letter % 10] + [int(char) for char in value[1:]]
    return sum(number * weight for number, weight in zip(numbers, TAIWAN_ID_WEIGHTS)) % 10 == 0


# 學號 / 校內識別碼：pii_scanner 沒有對應偵測器，保留在此並收斂規則。
# 必須帶「學號」關鍵字，避免任何 6-10 位數字（電話、金額、日期）誤判。
RULES = [
    Rule(
        "StudentNumber",
        re.compile(r"學號[:：\s]*([A-Z]{0,3}\d{6,12})\b", re.IGNORECASE),
        "Medium",
        "疑似學號或校內識別碼，公開前請確認。",
    ),
]


def mask_value(value: str) -> str:
    if "@" in value:
        local, _, domain = value.partition("@")
        return f"{local[:2]}***@{domain}"
    digits = sum(ch.isdigit() for ch in value)
    if digits >= 6:
        shown = 0
        masked = []
        for ch in value:
            if ch.isdigit():
                shown += 1
                masked.append(ch if shown <= 2 or shown > digits - 2 else "*")
            else:
                masked.append(ch)
        return "".join(masked)
    if len(value) <= 2:
        return "○" * len(value)
    return f"{value[0]}{'○' * max(1, len(value) - 2)}{value[-1]}"


# pii_scanner 偵測器名稱 -> (顯示用中文類別, 公開前建議)
_ENGINE_CATEGORY = {
    "taiwan_id": ("TaiwanNationalId", "疑似身分證字號，公開前請移除或遮罩。"),
    "taiwan_resident_cert": ("TaiwanResidentCertificate", "疑似居留證號，公開前請移除或遮罩。"),
    "taiwan_mobile": ("MobilePhone", "疑似手機號碼，公開前請確認是否有合法公開依據。"),
    "taiwan_landline": ("Landline", "疑似市話號碼，公開前請確認是否有合法公開依據。"),
    "email": ("Email", "疑似電子郵件，公開前請確認是否必要。"),
    "credit_card": ("CreditCard", "疑似信用卡號，公開前請務必移除或遮罩。"),
    "taiwan_business_id": ("BusinessId", "疑似統一編號，公開前請確認是否必要。"),
    "taiwan_passport": ("Passport", "疑似護照號碼，公開前請移除或遮罩。"),
    "taiwan_nhi_card": ("NHICard", "疑似健保卡號，公開前請移除或遮罩。"),
    "taiwan_license_plate": ("LicensePlate", "疑似車牌號碼，公開前請確認是否必要。"),
    "ipv4": ("IPAddress", "疑似 IP 位址，請確認是否需要公開。"),
    "ipv6": ("IPAddress", "疑似 IP 位址，請確認是否需要公開。"),
    "bank_account": ("BankAccount", "疑似銀行帳號，公開前請移除或遮罩。"),
    "date_of_birth": ("BirthDate", "疑似生日或日期型個資，公開前請確認。"),
    "taiwan_address": ("TaiwanAddress", "疑似地址，公開前請移除或遮罩。"),
    "chinese_name": ("PersonName", "疑似姓名，公開前請確認是否有公開依據。"),
    "surname_name": ("PersonName", "疑似姓名，公開前請確認是否有公開依據。"),
}

# pii_scanner severity -> 本系統風險等級
_SEVERITY_RISK = {"critical": "High", "high": "High", "medium": "Medium", "low": "Low"}


def _detect_with_engine(text: str, location: str) -> list[Finding]:
    """以 pii_scanner 完整偵測引擎掃描，並套用白名單後轉成本系統 Finding。"""
    from pii_scanner.detectors import detect_in_text
    from pii_scanner.whitelist import apply_whitelist

    findings: list[Finding] = []
    raw = detect_in_text(text, source=location)
    for item in apply_whitelist(raw):
        category, recommendation = _ENGINE_CATEGORY.get(
            item.detector, (item.category, "疑似個資，公開前請確認是否有公開依據。")
        )
        findings.append(
            Finding(
                detector=item.detector,
                category=category,
                risk_level=_SEVERITY_RISK.get(item.severity.value, "Medium"),
                confidence=0.9,
                masked_text=item.masked,
                location=location,
                recommendation=recommendation,
            )
        )
    return findings


def detect_with_rules(text: str, location: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()

    # 1) 完整偵測引擎（含 Luhn 信用卡、統編、護照、健保卡、車牌、姓名…）並套白名單
    for finding in _detect_with_engine(text, location):
        key = (finding.category, finding.masked_text, location)
        if key in seen:
            continue
        seen.add(key)
        findings.append(finding)

    # 2) 學號等校內識別碼（pii_scanner 未涵蓋）
    for rule in RULES:
        for match in rule.pattern.finditer(text):
            value = match.group(1) if rule.pattern.groups else match.group(0)
            masked = mask_value(value)
            key = (rule.category, masked, location)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    detector="local-rule",
                    category=rule.category,
                    risk_level=rule.risk_level,
                    confidence=0.92,
                    masked_text=masked,
                    location=location,
                    recommendation=rule.recommendation,
                )
            )
    return findings
