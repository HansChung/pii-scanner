from __future__ import annotations

import json
import math
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from flask import current_app

from .db import get_db

SERVICE_OCR = "documentIntelligence"
SERVICE_LANGUAGE = "language"
SERVICE_OPENAI = "openAi"


class UsageLimitExceeded(Exception):
    pass


def effective_settings() -> dict[str, Any]:
    rows = get_db().execute("SELECT key, value FROM settings").fetchall()
    values = {row["key"]: json.loads(row["value"]) for row in rows}
    return {
        "maxFileMb": int(values.get("maxFileMb", current_app.config["MAX_FILE_MB"])),
        "maxFilesPerUpload": int(
            values.get("maxFilesPerUpload", current_app.config["MAX_FILES_PER_UPLOAD"])
        ),
        "allowedExtensions": values.get(
            "allowedExtensions", sorted(current_app.config["ALLOWED_EXTENSIONS"])
        ),
        "highRiskThreshold": float(values.get("highRiskThreshold", 0.8)),
        "dailyUserJobLimit": int(
            values.get("dailyUserJobLimit", current_app.config["DAILY_USER_JOB_LIMIT"])
        ),
        "monthlyOcrPageLimit": int(
            values.get("monthlyOcrPageLimit", current_app.config["MONTHLY_OCR_PAGE_LIMIT"])
        ),
        "monthlyLanguageRecordLimit": int(
            values.get(
                "monthlyLanguageRecordLimit",
                current_app.config["MONTHLY_LANGUAGE_RECORD_LIMIT"],
            )
        ),
        "monthlyOpenAiTokenLimit": int(
            values.get(
                "monthlyOpenAiTokenLimit",
                current_app.config["MONTHLY_OPENAI_TOKEN_LIMIT"],
            )
        ),
        "documentIntelligenceEnabled": bool(values.get("documentIntelligenceEnabled", True)),
        "languagePiiEnabled": bool(values.get("languagePiiEnabled", True)),
        "openAiEnabled": bool(values.get("openAiEnabled", True)),
        "openAiEscalationOnly": bool(values.get("openAiEscalationOnly", True)),
    }


def usage_summary(actor: str | None = None) -> dict[str, Any]:
    settings = effective_settings()
    db = get_db()
    month_start = _month_start()
    day_start = _day_start()
    monthly_rows = db.execute(
        """
        SELECT service, COALESCE(SUM(units), 0) AS units
        FROM ai_usage WHERE created_at >= ? GROUP BY service
        """,
        (month_start,),
    ).fetchall()
    monthly = {row["service"]: int(row["units"]) for row in monthly_rows}
    today_jobs = 0
    if actor:
        today_jobs = int(
            db.execute(
                "SELECT COUNT(*) AS count FROM scan_jobs WHERE actor = ? AND created_at >= ?",
                (actor, day_start),
            ).fetchone()["count"]
        )
    return {
        "today": {"userJobs": today_jobs},
        "monthly": {
            "ocrPages": _usage_metric(monthly.get(SERVICE_OCR, 0), settings["monthlyOcrPageLimit"]),
            "languageRecords": _usage_metric(
                monthly.get(SERVICE_LANGUAGE, 0), settings["monthlyLanguageRecordLimit"]
            ),
            "openAiTokens": _usage_metric(
                monthly.get(SERVICE_OPENAI, 0), settings["monthlyOpenAiTokenLimit"]
            ),
        },
        "dailyUserJobLimit": settings["dailyUserJobLimit"],
    }


def estimate_files(files: list[dict[str, Any]]) -> dict[str, int]:
    ocr_pages = 0
    language_records = 0
    openai_tokens = 0
    for item in files:
        extension = str(item.get("extension", "")).lower()
        size = max(0, int(item.get("size", 0)))
        if extension in {".jpg", ".jpeg", ".png"}:
            ocr_pages += 1
        elif extension == ".pdf":
            ocr_pages += max(1, math.ceil(size / 100_000))
        elif extension in {".docx", ".pptx", ".xlsx"}:
            ocr_pages += min(3, max(0, math.ceil(size / 500_000)))
        records = max(1, math.ceil(size / 1000))
        language_records += records
        openai_tokens += min(2500, max(1, math.ceil(size / 4)) + 1000)
    return {
        "ocrPages": ocr_pages,
        "languageRecords": language_records,
        "openAiTokens": openai_tokens,
    }


def quota_check(actor: str, estimate: dict[str, int], include_daily_job: bool = True) -> list[str]:
    settings = effective_settings()
    summary = usage_summary(actor)
    errors = []
    if include_daily_job and summary["today"]["userJobs"] >= settings["dailyUserJobLimit"]:
        errors.append(f"今日查驗次數已達 {settings['dailyUserJobLimit']} 次上限。")
    if settings["documentIntelligenceEnabled"]:
        _append_quota_error(
            errors,
            "OCR 頁數",
            summary["monthly"]["ocrPages"]["used"],
            estimate["ocrPages"],
            settings["monthlyOcrPageLimit"],
        )
    if settings["languagePiiEnabled"]:
        _append_quota_error(
            errors,
            "Language Text Records",
            summary["monthly"]["languageRecords"]["used"],
            estimate["languageRecords"],
            settings["monthlyLanguageRecordLimit"],
        )
    if settings["openAiEnabled"]:
        _append_quota_error(
            errors,
            "GPT Token",
            summary["monthly"]["openAiTokens"]["used"],
            estimate["openAiTokens"],
            settings["monthlyOpenAiTokenLimit"],
        )
    return errors


def consume_usage(
    job_id: str,
    actor: str,
    service: str,
    units: int,
    unit_name: str,
    metadata: dict[str, Any] | None = None,
) -> None:
    units = max(0, int(units))
    if units == 0:
        return
    settings = effective_settings()
    limit = {
        SERVICE_OCR: settings["monthlyOcrPageLimit"],
        SERVICE_LANGUAGE: settings["monthlyLanguageRecordLimit"],
        SERVICE_OPENAI: settings["monthlyOpenAiTokenLimit"],
    }[service]
    db = get_db()
    try:
        db.execute("BEGIN IMMEDIATE")
        used = int(
            db.execute(
                "SELECT COALESCE(SUM(units), 0) AS units FROM ai_usage WHERE service = ? AND created_at >= ?",
                (service, _month_start()),
            ).fetchone()["units"]
        )
        if used + units > limit:
            raise UsageLimitExceeded(f"{_service_label(service)} 本月配額不足，已略過此外部 AI 服務。")
        db.execute(
            """
            INSERT INTO ai_usage (id, job_id, actor, service, units, unit_name, metadata, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                job_id,
                actor,
                service,
                units,
                unit_name,
                json.dumps(metadata or {}, ensure_ascii=False),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        db.commit()
    except Exception:
        db.rollback()
        raise


def job_usage(job_id: str) -> list[dict[str, Any]]:
    rows = get_db().execute(
        """
        SELECT service, units, unit_name, metadata, created_at
        FROM ai_usage WHERE job_id = ? ORDER BY created_at
        """,
        (job_id,),
    ).fetchall()
    return [
        {
            "service": row["service"],
            "units": row["units"],
            "unitName": row["unit_name"],
            "metadata": json.loads(row["metadata"]),
            "createdAt": row["created_at"],
        }
        for row in rows
    ]


def estimate_ocr_pages(path: Path, extension: str) -> int:
    if extension in {".jpg", ".jpeg", ".png"}:
        return 1
    if extension == ".pdf":
        try:
            from pypdf import PdfReader

            return max(1, len(PdfReader(str(path)).pages))
        except Exception:
            return max(1, math.ceil(path.stat().st_size / 100_000))
    return 1


def estimate_language_records(text: str) -> int:
    return max(1, math.ceil(len(text) / 1000))


def estimate_openai_tokens(text: str) -> int:
    return max(1, math.ceil(len(text) / 4) + 1000)


def _usage_metric(used: int, limit: int) -> dict[str, int]:
    return {"used": used, "limit": limit, "remaining": max(0, limit - used)}


def _append_quota_error(errors: list[str], label: str, used: int, estimate: int, limit: int) -> None:
    if used + estimate > limit:
        errors.append(f"{label} 本月剩餘配額不足。")


def _service_label(service: str) -> str:
    return {
        SERVICE_OCR: "OCR 頁數",
        SERVICE_LANGUAGE: "Language Text Records",
        SERVICE_OPENAI: "GPT Token",
    }[service]


def _day_start() -> str:
    now = datetime.now(_school_timezone())
    return now.replace(hour=0, minute=0, second=0, microsecond=0).astimezone(timezone.utc).isoformat()


def _month_start() -> str:
    now = datetime.now(_school_timezone())
    return (
        now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        .astimezone(timezone.utc)
        .isoformat()
    )


def _school_timezone() -> ZoneInfo:
    return ZoneInfo(current_app.config["SCHOOL_TIMEZONE"])
