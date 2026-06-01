from __future__ import annotations

import importlib
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from app import create_app

auth_module = importlib.import_module("app.auth")


class FakeMsalApp:
    def get_authorization_request_url(self, **kwargs: object) -> str:
        return f"https://login.example.test/authorize?redirect_uri={kwargs['redirect_uri']}"


def test_login_redirect_uses_forwarded_https_scheme(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("TEMP_UPLOAD_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("MS_CLIENT_ID", "client-id")
    monkeypatch.setenv("MS_CLIENT_SECRET", "client-secret")
    monkeypatch.setattr(auth_module, "_msal_app", lambda: FakeMsalApp())

    app = create_app()
    app.config.update(TESTING=True)

    with app.test_client() as client:
        response = client.get(
            "/auth/login",
            headers={
                "X-Forwarded-Host": "personaldata.example.test",
                "X-Forwarded-Proto": "https",
            },
        )

    query = parse_qs(urlparse(response.headers["Location"]).query)
    assert query["redirect_uri"] == ["https://personaldata.example.test/auth/callback"]


def test_login_redirect_defaults_to_https_without_forwarded_scheme(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("TEMP_UPLOAD_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("MS_CLIENT_ID", "client-id")
    monkeypatch.setenv("MS_CLIENT_SECRET", "client-secret")
    monkeypatch.setattr(auth_module, "_msal_app", lambda: FakeMsalApp())

    app = create_app()
    app.config.update(TESTING=True)

    with app.test_client() as client:
        response = client.get("/auth/login", headers={"Host": "personaldata.example.test"})

    query = parse_qs(urlparse(response.headers["Location"]).query)
    assert query["redirect_uri"] == ["https://personaldata.example.test/auth/callback"]
