"""IP 位址偵測。"""
from __future__ import annotations

import ipaddress
import re
from typing import Iterable

from .base import BaseDetector, Finding, Severity


class IPv4Detector(BaseDetector):
    name = "ipv4"
    category = "network"
    severity = Severity.LOW
    pattern = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")

    def detect(self, text: str) -> Iterable[Finding]:
        for m in self.pattern.finditer(text):
            value = m.group(0)
            try:
                addr = ipaddress.IPv4Address(value)
            except ValueError:
                continue
            if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
                continue
            yield self.make_finding(
                text,
                value=value,
                start=m.start(),
                end=m.end(),
                masked=".".join(value.split(".")[:2]) + ".*.*",
                notes="IPv4 位址",
            )


class IPv6Detector(BaseDetector):
    name = "ipv6"
    category = "network"
    severity = Severity.LOW
    pattern = re.compile(
        r"(?<![A-Za-z0-9:])(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}(?![A-Za-z0-9:])"
    )

    def detect(self, text: str) -> Iterable[Finding]:
        for m in self.pattern.finditer(text):
            value = m.group(0)
            try:
                addr = ipaddress.IPv6Address(value)
            except ValueError:
                continue
            if addr.is_loopback or addr.is_unspecified or addr.is_multicast:
                continue
            yield self.make_finding(
                text,
                value=value,
                start=m.start(),
                end=m.end(),
                masked=value.split(":")[0] + ":****",
                notes="IPv6 位址",
            )
