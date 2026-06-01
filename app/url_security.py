from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


class UnsafeUrlError(ValueError):
    pass


def validate_public_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise UnsafeUrlError("網站網址必須是完整的 http 或 https URL。")
    if parsed.username or parsed.password:
        raise UnsafeUrlError("網站網址不可包含帳號或密碼。")
    hostname = parsed.hostname.rstrip(".").lower()
    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise UnsafeUrlError("不可掃描本機或內部網路網址。")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(hostname, parsed.port)}
    except socket.gaierror as exc:
        raise UnsafeUrlError("無法解析網站網域名稱。") from exc
    if not addresses:
        raise UnsafeUrlError("無法解析網站網域名稱。")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise UnsafeUrlError("不可掃描本機或內部網路網址。")
