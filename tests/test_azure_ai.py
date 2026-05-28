"""Azure AI 增強分析（mock 測試）。"""

from pii_scanner.ai.azure_language import merge_ai_findings
from pii_scanner.ai.enhance import maybe_enhance_with_ai
from pii_scanner.detectors.base import Finding, Severity


def _finding(**kw):
    defaults = dict(
        detector="taiwan_mobile",
        category="phone",
        severity=Severity.HIGH,
        value="0912345678",
        masked="0912****78",
        start=0,
        end=10,
    )
    defaults.update(kw)
    return Finding(**defaults)


def test_maybe_enhance_skips_when_not_requested():
    base = [_finding()]
    out, meta = maybe_enhance_with_ai("0912345678", base, use_ai=False)
    assert len(out) == 1
    assert not meta.ai_used


def test_maybe_enhance_warns_when_not_configured(monkeypatch):
    monkeypatch.setattr("pii_scanner.ai.enhance.is_ai_configured", lambda: False)
    out, meta = maybe_enhance_with_ai("test", [], use_ai=True)
    assert meta.ai_requested
    assert meta.ai_warning


def test_merge_ai_dedupes_overlap():
    base = [_finding(start=5, end=8, category="name", detector="chinese_name", value="王小明", masked="王**", severity=Severity.LOW)]
    ai = [_finding(start=5, end=8, category="name", detector="azure_ai_pii", value="王小明", masked="王*明", severity=Severity.LOW)]
    merged = merge_ai_findings(base, ai)
    assert len(merged) == 1
