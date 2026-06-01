from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from flask import current_app

from .db import get_db

SECRET_KEYS = {
    "azureDocumentIntelligenceKey",
    "azureLanguageKey",
    "azureOpenAiKey",
}

AZURE_AI_FIELDS = {
    "azureDocumentIntelligenceEndpoint": "AZURE_DOCUMENT_INTELLIGENCE_ENDPOINT",
    "azureDocumentIntelligenceKey": "AZURE_DOCUMENT_INTELLIGENCE_KEY",
    "azureDocumentIntelligenceApiVersion": "AZURE_DOCUMENT_INTELLIGENCE_API_VERSION",
    "azureLanguageEndpoint": "AZURE_LANGUAGE_ENDPOINT",
    "azureLanguageKey": "AZURE_LANGUAGE_KEY",
    "azureLanguageApiVersion": "AZURE_LANGUAGE_API_VERSION",
    "azureOpenAiEndpoint": "AZURE_OPENAI_ENDPOINT",
    "azureOpenAiKey": "AZURE_OPENAI_KEY",
    "azureOpenAiDeployment": "AZURE_OPENAI_DEPLOYMENT",
    "azureOpenAiApiVersion": "AZURE_OPENAI_API_VERSION",
}


def _fernet() -> Fernet:
    digest = hashlib.sha256(current_app.config["SECRET_KEY"].encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def _setting_key(name: str) -> str:
    return f"azureAi.{name}"


def _env_value(name: str) -> str:
    env_name = AZURE_AI_FIELDS[name]
    value = current_app.config.get(env_name, "")
    return str(value or "")


def get_secret_or_setting(name: str) -> str:
    db = get_db()
    row = db.execute("SELECT value FROM settings WHERE key = ?", (_setting_key(name),)).fetchone()
    if not row:
        return _env_value(name)
    raw = json.loads(row["value"])
    if name in SECRET_KEYS:
        try:
            return _fernet().decrypt(str(raw["ciphertext"]).encode("utf-8")).decode("utf-8")
        except (InvalidToken, KeyError, TypeError):
            return ""
    return str(raw.get("value", ""))


def effective_azure_ai_config() -> dict[str, str]:
    return {name: get_secret_or_setting(name) for name in AZURE_AI_FIELDS}


def public_azure_ai_config() -> dict[str, Any]:
    config = effective_azure_ai_config()
    result: dict[str, Any] = {}
    for name, value in config.items():
        if name in SECRET_KEYS:
            result[name] = {
                "configured": bool(value),
                "masked": _mask_secret(value) if value else "",
            }
        else:
            result[name] = value
    return result


def update_azure_ai_config(payload: dict[str, Any]) -> None:
    db = get_db()
    for name in AZURE_AI_FIELDS:
        if name not in payload:
            continue
        value = str(payload.get(name) or "").strip()
        if name in SECRET_KEYS:
            if not value:
                continue
            stored = {
                "encrypted": True,
                "ciphertext": _fernet().encrypt(value.encode("utf-8")).decode("utf-8"),
            }
        else:
            stored = {"value": value}
        db.execute(
            """
            INSERT INTO settings (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (_setting_key(name), json.dumps(stored, ensure_ascii=False)),
        )


def clear_azure_secret(name: str) -> None:
    if name not in SECRET_KEYS:
        return
    get_db().execute("DELETE FROM settings WHERE key = ?", (_setting_key(name),))


def _mask_secret(value: str) -> str:
    if len(value) <= 8:
        return "••••"
    return f"{value[:4]}••••{value[-4:]}"

