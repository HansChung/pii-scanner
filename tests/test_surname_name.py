"""百家姓姓名偵測器測試。"""
from __future__ import annotations

from pii_scanner import scan_text
from pii_scanner.detectors.surname_name import (
    SurnameMatchMode,
    SurnameNameDetector,
    find_surname_names,
)


def _names(findings):
    return [f for f in findings if f.detector == "surname_name"]


def test_surname_detects_bare_name():
    # 句首或標點後較不易誤判；嵌入詞（淡江、國際）仍可能誤判，故預設關閉 surname_name
    findings = SurnameNameDetector().detect("王小明主持，陳大文也出席。")
    values = {f.value for f in findings}
    assert "王小明" in values
    assert "陳大文" in values


def test_surname_compound_name():
    findings = SurnameNameDetector().detect("聯絡人歐陽修將於明日到訪。")
    values = {f.value for f in findings}
    assert "歐陽修" in values


def test_surname_rejects_stopword():
    findings = SurnameNameDetector().detect("請提交陳情書至服務台。")
    assert not _names(findings)


def test_surname_rejects_institution_suffix():
    findings = SurnameNameDetector().detect("前往王公司洽公。")
    assert not any(f.value == "王公司" for f in findings)


def test_surname_rejects_honorific_in_balanced():
    findings = SurnameNameDetector(mode=SurnameMatchMode.BALANCED).detect("王先生來電。")
    # balanced 模式會因「先生」後綴過濾掉「王」開頭的 2 字片段
    assert not any(f.value in ("王先", "王先生") for f in findings)


def test_surname_strict_requires_boundary():
    text = "x王小明y"
    strict = find_surname_names(text, mode=SurnameMatchMode.STRICT)
    balanced = find_surname_names(text, mode=SurnameMatchMode.BALANCED)
    assert not strict
    assert balanced


def test_surname_masks_output():
    findings = list(SurnameNameDetector().detect("承辦人林佳蓉已完成。"))
    assert findings
    assert "*" in findings[0].masked
    assert "林佳蓉" not in findings[0].masked


def test_scan_text_excludes_surname_name_by_default():
    findings = scan_text("今日由張三完成報告。")
    detectors = {f.detector for f in findings}
    assert "surname_name" not in detectors


def test_scan_text_includes_surname_name_when_enabled():
    from pii_scanner.detectors import get_active_detectors

    dets = get_active_detectors(include_surname=True)
    findings = scan_text("王小明完成報告。", detectors=dets)
    assert any(f.detector == "surname_name" for f in findings)


def test_dedupe_keyword_and_surname_same_span():
    findings = scan_text("姓名: 王小明")
    names = [f for f in findings if f.category == "name"]
    # 同一 span 只保留一筆
    spans = {(f.start, f.end) for f in names}
    assert len(spans) == len(names)
