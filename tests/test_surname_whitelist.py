"""白名單啟用 surname_name 與 get_active_detectors 連動測試。"""

from pii_scanner.detectors import get_active_detectors
from pii_scanner.detectors.surname_name import SurnameNameDetector
from pii_scanner.scanners.text_scanner import scan_text
from pii_scanner.whitelist import WhitelistConfig, apply_whitelist


def _reset_whitelist_cache(monkeypatch, cfg_path):
    monkeypatch.setattr("pii_scanner.whitelist.store.WHITELIST_PATH", cfg_path)
    monkeypatch.setattr("pii_scanner.whitelist.store._cache_config", None)
    monkeypatch.setattr("pii_scanner.whitelist.store._cache_mtime", -2.0)


def test_whitelist_removed_disable_enables_surname_detector(monkeypatch, tmp_path):
    cfg_path = tmp_path / "wl.json"
    cfg_path.write_text('{"version":1,"global_disabled_detectors":[],"ignore_words":[],"domain_rules":[]}', encoding="utf-8")
    _reset_whitelist_cache(monkeypatch, cfg_path)
    monkeypatch.setattr("pii_scanner.settings.ENABLE_SURNAME_NAME", False)

    names = {d.name for d in get_active_detectors()}
    assert "surname_name" in names


def test_whitelist_disabled_blocks_surname_detector(monkeypatch, tmp_path):
    cfg_path = tmp_path / "wl.json"
    cfg_path.write_text(
        '{"version":1,"global_disabled_detectors":["surname_name"],"ignore_words":[],"domain_rules":[]}',
        encoding="utf-8",
    )
    _reset_whitelist_cache(monkeypatch, cfg_path)
    monkeypatch.setattr("pii_scanner.settings.ENABLE_SURNAME_NAME", True)

    names = {d.name for d in get_active_detectors()}
    assert "surname_name" not in names


def test_surname_finding_survives_when_enabled_in_whitelist(monkeypatch, tmp_path):
    cfg_path = tmp_path / "wl.json"
    cfg_path.write_text(
        '{"version":1,"global_disabled_detectors":[],"ignore_words":[],"domain_rules":[]}',
        encoding="utf-8",
    )
    _reset_whitelist_cache(monkeypatch, cfg_path)
    monkeypatch.setattr("pii_scanner.settings.ENABLE_SURNAME_NAME", False)

    findings = scan_text(
        "學生王小明完成註冊。",
        source="https://example.com/page",
        detectors=get_active_detectors(),
    )
    cfg = WhitelistConfig.from_dict({"global_disabled_detectors": [], "ignore_words": [], "domain_rules": []})
    out = apply_whitelist(findings, config=cfg)
    assert any(f.detector == "surname_name" for f in out)
