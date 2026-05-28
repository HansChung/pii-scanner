"""頁尾／承辦人脈絡人名偵測測試。"""

from pii_scanner.detectors.context_name import ContextNameDetector


def test_footer_maintenance_and_web_builder():
    text = """
    資料維護：秘書處 江雅玲
    網頁建置：資訊處 張秀榕
    """
    d = ContextNameDetector()
    matches = d.detect(text)
    names = {m.value for m in matches}
    assert "江雅玲" in names
    assert "張秀榕" in names


def test_contact_person_label():
    text = "承辦人：王小明 電話：02-2621-5656"
    d = ContextNameDetector()
    matches = d.detect(text)
    assert any(m.value == "王小明" for m in matches)


def test_does_not_match_department_only():
    text = "資料維護：秘書處"
    d = ContextNameDetector()
    assert list(d.detect(text)) == []
