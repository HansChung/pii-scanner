"""依法公開聯絡/維護資訊之姓名排除測試。"""

from pii_scanner.detectors import detect_in_text
from pii_scanner.detectors.surname_name import SurnameNameDetector
from pii_scanner.filters.public_disclosure import is_public_disclosure_name


def test_footer_maintenance_names_excluded_when_surname_enabled(monkeypatch):
    monkeypatch.setattr("pii_scanner.settings.ENABLE_SURNAME_NAME", True)
    text = """
    資料維護：秘書處 江雅玲
    網頁建置：資訊處 張秀榕
    """
    findings = detect_in_text(text, detectors=[SurnameNameDetector()])
    names = {f.value for f in findings if f.category == "name"}
    assert "江雅玲" not in names
    assert "張秀榕" not in names


def test_contact_person_excluded(monkeypatch):
    monkeypatch.setattr("pii_scanner.settings.ENABLE_SURNAME_NAME", True)
    text = "承辦人：王小明 電話：02-2621-5656"
    findings = detect_in_text(text, detectors=[SurnameNameDetector()])
    assert not any(f.category == "name" for f in findings)


def test_private_name_still_detected(monkeypatch):
    monkeypatch.setattr("pii_scanner.settings.ENABLE_SURNAME_NAME", True)
    text = "本系學生江雅玲已通過口試。"
    findings = detect_in_text(text, detectors=[SurnameNameDetector()])
    assert any(f.value == "江雅玲" for f in findings)


def test_is_public_disclosure_helper():
    text = "資料維護：秘書處 江雅玲"
    idx = text.index("江雅玲")
    assert is_public_disclosure_name(text, idx, idx + len("江雅玲"))
