"""白名單過濾測試。"""
from pii_scanner.detectors.base import Finding, Severity
from pii_scanner.whitelist import WhitelistConfig, DomainRule, apply_whitelist


def _finding(detector: str, value: str, source: str = "https://www.tku.edu.tw/page") -> Finding:
    return Finding(
        detector=detector,
        category="test",
        severity=Severity.LOW,
        value=value,
        masked=value,
        start=0,
        end=len(value),
        source=source,
    )


def test_global_disable_detector():
    cfg = WhitelistConfig(global_disabled_detectors=["surname_name"])
    findings = [
        _finding("surname_name", "張三"),
        _finding("email", "a@b.com"),
    ]
    out = apply_whitelist(findings, config=cfg)
    assert len(out) == 1
    assert out[0].detector == "email"


def test_domain_rule_disable():
    cfg = WhitelistConfig(
        domain_rules=[
            DomainRule(domain="tku.edu.tw", disabled_detectors=["taiwan_address"]),
        ]
    )
    findings = [
        _finding("taiwan_address", "新北市淡水域", source="https://www.tku.edu.tw/"),
        _finding("email", "x@tku.edu.tw", source="https://www.tku.edu.tw/"),
    ]
    out = apply_whitelist(findings, config=cfg)
    assert len(out) == 1
    assert out[0].detector == "email"


def test_ignore_word():
    cfg = WhitelistConfig(ignore_words=["president@mail.tku.edu.tw"])
    findings = [_finding("email", "president@mail.tku.edu.tw")]
    out = apply_whitelist(findings, config=cfg)
    assert len(out) == 0
