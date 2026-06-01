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


RULES = [
    Rule(
        "TaiwanNationalId",
        re.compile(r"\b[A-Z][12]\d{8}\b", re.IGNORECASE),
        "High",
        "疑似身分證字號，公開前請移除或遮罩。",
    ),
    Rule(
        "TaiwanResidentCertificate",
        re.compile(r"\b[A-Z][A-D]\d{8}\b", re.IGNORECASE),
        "High",
        "疑似居留證號，公開前請移除或遮罩。",
    ),
    Rule(
        "MobilePhone",
        re.compile(r"\b09\d{2}[-\s]?\d{3}[-\s]?\d{3}\b"),
        "High",
        "疑似手機號碼，公開前請確認是否有合法公開依據。",
    ),
    Rule(
        "Email",
        re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
        "Medium",
        "疑似電子郵件，公開前請確認是否必要。",
    ),
    Rule(
        "BirthDate",
        re.compile(r"\b(?:19|20)\d{2}[-/.年](?:0?[1-9]|1[0-2])[-/.月](?:0?[1-9]|[12]\d|3[01])日?\b"),
        "High",
        "疑似生日或日期型個資，公開前請確認。",
    ),
    Rule(
        "StudentNumber",
        re.compile(r"\b(?:學號[:：\s]*)?[A-Z]?\d{6,10}\b", re.IGNORECASE),
        "Medium",
        "疑似學號或校內識別碼，公開前請確認。",
    ),
    Rule(
        "BankAccount",
        re.compile(r"\b\d{3}[-\s]?\d{4}[-\s]?\d{5,8}\b"),
        "High",
        "疑似銀行帳號，公開前請移除或遮罩。",
    ),
    Rule(
        "IPAddress",
        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "Low",
        "疑似 IP 位址，請確認是否需要公開。",
    ),
    Rule(
        "TaiwanAddress",
        re.compile(r"[^\s，,。]{2,}(?:縣|市)[^\s，,。]{2,}(?:鄉|鎮|市|區)[^\s，,。]{1,}(?:路|街|大道|巷|弄)\S{0,20}"),
        "High",
        "疑似地址，公開前請移除或遮罩。",
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


def detect_with_rules(text: str, location: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for rule in RULES:
        for match in rule.pattern.finditer(text):
            value = match.group(0)
            if rule.category == "TaiwanNationalId" and not validate_taiwan_id(value):
                continue
            key = (rule.category, value, location)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    detector="local-rule",
                    category=rule.category,
                    risk_level=rule.risk_level,
                    confidence=0.92,
                    masked_text=mask_value(value),
                    location=location,
                    recommendation=rule.recommendation,
                )
            )
    return findings
