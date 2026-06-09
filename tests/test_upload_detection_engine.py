"""驗證上傳檔案查驗已改用 pii_scanner 完整偵測引擎並套用白名單。"""
from __future__ import annotations

from app.pii_rules import detect_with_rules
from pii_scanner.whitelist import WhitelistConfig


def _categories(text: str) -> list[str]:
    return [finding.category for finding in detect_with_rules(text, "測試")]


def test_credit_card_uses_luhn():
    # 通過 Luhn 的卡號應命中，未通過的不應命中
    assert "CreditCard" in _categories("付款卡號 4111111111111111")
    assert "CreditCard" not in _categories("流水號 4111111111111112")


def test_covers_extended_taiwan_pii_types():
    cats = _categories(
        "統編 04595257 護照號碼 131234567 健保卡 0000123456789 車牌 ABC-1234"
    )
    assert "BusinessId" in cats
    assert "Passport" in cats
    assert "NHICard" in cats
    assert "LicensePlate" in cats


def test_taiwan_id_still_validated_by_checksum():
    cats = _categories("正確 A123456789 錯誤 A123456788")
    assert cats.count("TaiwanNationalId") == 1


def test_student_number_requires_keyword():
    # 帶「學號」關鍵字才命中，避免任何長數字誤判
    assert "StudentNumber" in _categories("學號：B12345678")
    assert "StudentNumber" not in _categories("金額 1234567 與電話 0287654321")


def test_whitelist_applied_to_uploaded_files(monkeypatch):
    # 上傳檔案也要套用白名單：停用 email 偵測器後，email 不應命中
    import pii_scanner.whitelist.store as store

    cfg = WhitelistConfig(global_disabled_detectors=["surname_name", "email"])
    monkeypatch.setattr(store, "load_whitelist", lambda *a, **k: cfg)

    findings = detect_with_rules("聯絡 user@tku.edu.tw 身分證 A123456789", "測試")
    cats = [f.category for f in findings]
    assert "Email" not in cats  # 被白名單停用
    assert "TaiwanNationalId" in cats  # 未被停用者仍命中
