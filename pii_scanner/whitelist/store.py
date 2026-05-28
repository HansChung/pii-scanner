"""白名單：管理略過的偵測器、詞彙、網域規則。"""
from __future__ import annotations

import json
import os
import re
import threading
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

from ..detectors.base import Finding
from ..settings import WHITELIST_PATH

DEFAULT_CONFIG = {
    "version": 1,
    "global_disabled_detectors": ["surname_name"],
    "ignore_words": [],
    "domain_rules": [],
}


@dataclass
class DomainRule:
    domain: str
    disabled_detectors: List[str] = field(default_factory=list)
    ignore_words: List[str] = field(default_factory=list)


@dataclass
class WhitelistConfig:
    version: int = 1
    global_disabled_detectors: List[str] = field(default_factory=lambda: ["surname_name"])
    ignore_words: List[str] = field(default_factory=list)
    domain_rules: List[DomainRule] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "global_disabled_detectors": list(self.global_disabled_detectors),
            "ignore_words": list(self.ignore_words),
            "domain_rules": [
                {
                    "domain": r.domain,
                    "disabled_detectors": list(r.disabled_detectors),
                    "ignore_words": list(r.ignore_words),
                }
                for r in self.domain_rules
            ],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "WhitelistConfig":
        rules = [
            DomainRule(
                domain=r["domain"],
                disabled_detectors=list(r.get("disabled_detectors", [])),
                ignore_words=list(r.get("ignore_words", [])),
            )
            for r in data.get("domain_rules", [])
            if r.get("domain")
        ]
        return cls(
            version=int(data.get("version", 1)),
            global_disabled_detectors=list(
                data.get("global_disabled_detectors", DEFAULT_CONFIG["global_disabled_detectors"])
            ),
            ignore_words=list(data.get("ignore_words", [])),
            domain_rules=rules,
        )


_lock = threading.Lock()


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def load_whitelist(path: Optional[Path] = None) -> WhitelistConfig:
    p = path or WHITELIST_PATH
    with _lock:
        if not p.exists():
            cfg = WhitelistConfig.from_dict(DEFAULT_CONFIG)
            save_whitelist(cfg, path=p)
            return cfg
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return WhitelistConfig.from_dict(DEFAULT_CONFIG)
        return WhitelistConfig.from_dict(data)


def save_whitelist(config: WhitelistConfig, path: Optional[Path] = None) -> None:
    p = path or WHITELIST_PATH
    with _lock:
        _ensure_parent(p)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(config.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(p)


def _domain_from_source(source: Optional[str]) -> Optional[str]:
    if not source or "://" not in source:
        return None
    try:
        host = urlparse(source).netloc.lower()
        return host[4:] if host.startswith("www.") else host
    except Exception:
        return None


def _domain_matches(source_domain: Optional[str], rule_domain: str) -> bool:
    if not source_domain:
        return False
    rule = rule_domain.lower().strip()
    src = source_domain.lower()
    return src == rule or src.endswith("." + rule)


def _word_in_finding(word: str, finding: Finding) -> bool:
    w = word.strip()
    if not w:
        return False
    return w in finding.value or w in finding.context or w in (finding.source or "")


def apply_whitelist(
    findings: List[Finding],
    config: Optional[WhitelistConfig] = None,
) -> List[Finding]:
    """依白名單過濾命中結果。"""
    cfg = config or load_whitelist()
    global_disabled = set(cfg.global_disabled_detectors)
    global_words = set(cfg.ignore_words)
    out: List[Finding] = []

    for f in findings:
        if f.detector in global_disabled:
            continue
        if any(_word_in_finding(w, f) for w in global_words):
            continue

        source_domain = _domain_from_source(f.source)
        skip = False
        for rule in cfg.domain_rules:
            if not _domain_matches(source_domain, rule.domain):
                continue
            if f.detector in rule.disabled_detectors:
                skip = True
                break
            if any(_word_in_finding(w, f) for w in rule.ignore_words):
                skip = True
                break
        if not skip:
            out.append(f)
    return out


def list_known_detectors() -> List[str]:
    from ..detectors import ALL_DETECTORS, get_active_detectors

    names = {d.name for d in ALL_DETECTORS}
    names.update(d.name for d in get_active_detectors())
    return sorted(names)
