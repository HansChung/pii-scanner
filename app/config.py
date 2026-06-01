from __future__ import annotations

import os
from pathlib import Path


class Config:
    def __init__(self) -> None:
        base_dir = Path(__file__).resolve().parent.parent
        self.SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-only-change-me")
        self.BASE_DIR = base_dir
        self.DATABASE_PATH = os.getenv("DATABASE_PATH", str(base_dir / "instance" / "app.db"))
        self.TEMP_UPLOAD_DIR = os.getenv("TEMP_UPLOAD_DIR", str(base_dir / "tmp" / "uploads"))
        self.MAX_FILE_MB = int(os.getenv("MAX_FILE_MB", "25"))
        self.MAX_FILES_PER_UPLOAD = int(os.getenv("MAX_FILES_PER_UPLOAD", "5"))
        self.MAX_CONTENT_LENGTH = self.MAX_FILE_MB * self.MAX_FILES_PER_UPLOAD * 1024 * 1024
        self.ALLOWED_EXTENSIONS = {
            item.strip().lower()
            for item in os.getenv(
                "ALLOWED_EXTENSIONS",
                ".pdf,.docx,.pptx,.xlsx,.csv,.txt,.jpg,.jpeg,.png",
            ).split(",")
            if item.strip()
        }
        self.CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")
        self.JOB_TIMEOUT_SECONDS = int(os.getenv("JOB_TIMEOUT_SECONDS", "180"))
        self.AUTH_REQUIRED = os.getenv("AUTH_REQUIRED", "true").lower() not in {"0", "false", "no"}
        self.MS_TENANT_ID = os.getenv("MS_TENANT_ID", "common")
        self.MS_CLIENT_ID = os.getenv("MS_CLIENT_ID", "")
        self.MS_CLIENT_SECRET = os.getenv("MS_CLIENT_SECRET", "")
        self.MS_REDIRECT_PATH = os.getenv("MS_REDIRECT_PATH", "/auth/callback")
        self.MS_AUTHORITY = os.getenv(
            "MS_AUTHORITY",
            f"https://login.microsoftonline.com/{self.MS_TENANT_ID}",
        )
        self.MS_SCOPES = [
            item.strip()
            for item in os.getenv("MS_SCOPES", "User.Read").split(",")
            if item.strip()
        ]
        self.ADMIN_EMAILS = {
            item.strip().lower()
            for item in os.getenv("ADMIN_EMAILS", "").split(",")
            if item.strip()
        }
        self.AZURE_DOCUMENT_INTELLIGENCE_ENDPOINT = os.getenv(
            "AZURE_DOCUMENT_INTELLIGENCE_ENDPOINT", ""
        )
        self.AZURE_DOCUMENT_INTELLIGENCE_KEY = os.getenv("AZURE_DOCUMENT_INTELLIGENCE_KEY", "")
        self.AZURE_DOCUMENT_INTELLIGENCE_API_VERSION = os.getenv(
            "AZURE_DOCUMENT_INTELLIGENCE_API_VERSION", "2024-11-30"
        )
        self.AZURE_LANGUAGE_ENDPOINT = os.getenv("AZURE_LANGUAGE_ENDPOINT", "")
        self.AZURE_LANGUAGE_KEY = os.getenv("AZURE_LANGUAGE_KEY", "")
        self.AZURE_LANGUAGE_API_VERSION = os.getenv(
            "AZURE_LANGUAGE_API_VERSION", "2024-11-15-preview"
        )
        self.AZURE_OPENAI_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT", "")
        self.AZURE_OPENAI_KEY = os.getenv("AZURE_OPENAI_KEY", "")
        self.AZURE_OPENAI_DEPLOYMENT = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-5-mini")
        self.AZURE_OPENAI_API_VERSION = os.getenv("AZURE_OPENAI_API_VERSION", "2025-04-01-preview")
