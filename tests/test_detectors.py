"""針對各 PII 偵測器與報表渲染的單元測試。"""
from __future__ import annotations

import json

from pii_scanner import detect_in_text, scan_text
from pii_scanner.detectors.taiwan_id import validate_taiwan_id, validate_resident_cert_new
from pii_scanner.detectors.tax_id import validate_business_id
from pii_scanner.detectors.credit_card import luhn_check
from pii_scanner.report import render_html, render_json, render_terminal


def detectors_named(findings, name):
    return [f for f in findings if f.detector == name]


def test_taiwan_id_validation():
    assert validate_taiwan_id("A123456789")
    assert not validate_taiwan_id("A123456788")
    assert not validate_taiwan_id("Z000000000")


def test_resident_cert_new():
    """A800000014 是官方範例之外，這邊用已知合法樣本檢查機制本身可運作。"""
    valid = []
    for i in range(0, 100000000):
        cand = f"AB{i:08d}"
        if validate_resident_cert_new(cand):
            valid.append(cand)
            break
    assert valid, "新版居留證演算法應能產出至少一個合法號碼"


def test_business_id_validation():
    assert validate_business_id("12345675")
    assert not validate_business_id("12345678")


def test_luhn_check():
    assert luhn_check("4111111111111111")
    assert not luhn_check("4111111111111112")


def test_scan_text_full_sample():
    text = (
        "客戶 姓名: 王小明 身分證 A123456789 "
        "手機 0912-345-678 Email a@example.com "
        "信用卡 4111-1111-1111-1111 統編 12345675 "
        "地址 台北市大安區忠孝東路四段100號 "
        "車牌 ABC-1234 IP 203.0.113.42 "
        "護照號碼 123456789 健保卡號 123456789012 "
        "生日 1990/01/15 帳號: 123-456-789012"
    )
    findings = scan_text(text)
    by = {f.detector for f in findings}
    assert "taiwan_id" in by
    assert "taiwan_mobile" in by
    assert "email" in by
    assert "credit_card" in by
    assert "taiwan_business_id" in by
    assert "taiwan_license_plate" in by
    assert "ipv4" in by
    assert "taiwan_passport" in by
    assert "taiwan_nhi_card" in by
    assert "date_of_birth" in by
    assert "bank_account" in by
    assert "chinese_name" in by
    assert "taiwan_address" in by


def test_email_detection_and_mask():
    findings = scan_text("聯絡: alice.smith@example.com.tw")
    emails = detectors_named(findings, "email")
    assert len(emails) == 1
    assert "@example.com.tw" in emails[0].masked
    assert "alice.smith" not in emails[0].masked


def test_mobile_with_country_code():
    findings = scan_text("call me at +886 912 345 678 please")
    mob = detectors_named(findings, "taiwan_mobile")
    assert mob


def test_credit_card_rejects_invalid():
    findings = scan_text("卡號 1234 5678 9012 3456")
    assert not detectors_named(findings, "credit_card")


def test_ipv4_skips_loopback():
    findings = scan_text("server 127.0.0.1 vs 8.8.8.8")
    ips = detectors_named(findings, "ipv4")
    assert any(f.value == "8.8.8.8" for f in ips)
    assert not any(f.value == "127.0.0.1" for f in ips)


def test_render_json_is_parseable():
    findings = scan_text("身分證 A123456789")
    data = json.loads(render_json(findings))
    assert data["summary"]["total"] >= 1
    assert data["findings"][0]["masked"].startswith("A1")


def test_render_html_contains_value():
    findings = scan_text("身分證 A123456789")
    html = render_html(findings)
    assert "PII 掃描報告" in html
    assert "taiwan_id" in html


def test_render_terminal_no_color():
    findings = scan_text("身分證 A123456789")
    text = render_terminal(findings, use_color=False)
    assert "CRITICAL" in text or "critical" in text
    assert "A1" in text


def test_masking_does_not_leak_full_value():
    findings = scan_text("身分證 A123456789 信用卡 4111-1111-1111-1111")
    for f in findings:
        if f.severity.value in ("critical", "high"):
            assert "*" in f.masked
