from __future__ import annotations

import hashlib
import json
import shutil
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from flask import current_app

from .azure_services import (
    azure_openai_enabled,
    detect_school_context_with_openai,
    detect_with_azure_language,
    document_intelligence_enabled,
    extract_with_document_intelligence,
    language_pii_enabled,
)
from .db import get_db
from .extractors import extract_text
from .models import Finding
from .pii_rules import detect_with_rules

executor = ThreadPoolExecutor(max_workers=2)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def submit_scan(job_id: str, upload_records: list[dict[str, str]]) -> None:
    app = current_app._get_current_object()
    if app.config.get("TESTING"):
        _run_with_context(app, job_id, upload_records)
        return
    executor.submit(_run_with_context, app, job_id, upload_records)


def _run_with_context(app, job_id: str, upload_records: list[dict[str, str]]) -> None:
    with app.app_context():
        run_scan(job_id, upload_records)


def run_scan(job_id: str, upload_records: list[dict[str, str]]) -> None:
    db = get_db()
    temp_paths = [Path(record["path"]) for record in upload_records]
    try:
        _update_job(job_id, "processing", 10, "開始抽取文字與 OCR")
        all_findings: list[tuple[str, Finding]] = []
        for index, record in enumerate(upload_records, start=1):
            file_id = record["file_id"]
            path = Path(record["path"])
            extension = record["extension"]
            chunks = extract_text(path, extension)
            if extension in {".pdf", ".jpg", ".jpeg", ".png"} and document_intelligence_enabled():
                try:
                    ocr_chunks = extract_with_document_intelligence(path)
                    chunks.extend(ocr_chunks)
                except Exception as exc:
                    _set_file_error(file_id, f"OCR 失敗：{exc}")
            for chunk in chunks:
                all_findings.extend((file_id, finding) for finding in detect_with_rules(chunk.text, chunk.location))
                if language_pii_enabled():
                    try:
                        all_findings.extend(
                            (file_id, finding)
                            for finding in detect_with_azure_language(chunk.text, chunk.location)
                        )
                    except Exception as exc:
                        _set_file_error(file_id, f"Azure Language PII 失敗：{exc}")
                if azure_openai_enabled():
                    try:
                        all_findings.extend(
                            (file_id, finding)
                            for finding in detect_school_context_with_openai(chunk.text, chunk.location)
                        )
                    except Exception as exc:
                        _set_file_error(file_id, f"Azure OpenAI 失敗：{exc}")
            _update_job(job_id, "processing", 10 + int(index / len(upload_records) * 75), "查驗中")

        deduped = _dedupe_findings(all_findings)
        for file_id, finding in deduped:
            db.execute(
                """
                INSERT INTO findings
                (id, job_id, file_id, detector, category, risk_level, confidence, masked_text,
                 location, recommendation, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    job_id,
                    file_id,
                    finding.detector,
                    finding.category,
                    finding.risk_level,
                    finding.confidence,
                    finding.masked_text,
                    finding.location,
                    finding.recommendation,
                    now_iso(),
                ),
            )
        risk_level = _overall_risk([finding for _, finding in deduped])
        db.execute(
            "UPDATE files SET status = 'completed' WHERE job_id = ? AND status != 'failed'",
            (job_id,),
        )
        db.execute(
            """
            UPDATE scan_jobs
            SET status = 'completed', progress = 100, message = ?, risk_level = ?,
                updated_at = ?, completed_at = ?
            WHERE id = ?
            """,
            ("查驗完成", risk_level, now_iso(), now_iso(), job_id),
        )
        _audit("system", "scan_completed", "scan_job", job_id, {"findings": len(deduped)})
        db.commit()
    except Exception as exc:
        db.execute(
            """
            UPDATE scan_jobs
            SET status = 'failed', progress = 100, message = ?, updated_at = ?, completed_at = ?
            WHERE id = ?
            """,
            (f"查驗失敗：{exc}", now_iso(), now_iso(), job_id),
        )
        _audit("system", "scan_failed", "scan_job", job_id, {"error": str(exc)})
        db.commit()
    finally:
        for path in temp_paths:
            try:
                path.unlink(missing_ok=True)
            except TypeError:
                if path.exists():
                    path.unlink()
        for path in {item.parent for item in temp_paths}:
            shutil.rmtree(path, ignore_errors=True)


def create_file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _dedupe_findings(items: list[tuple[str, Finding]]) -> list[tuple[str, Finding]]:
    seen: set[tuple[str, str, str, str]] = set()
    result = []
    for file_id, finding in items:
        key = (file_id, finding.category, finding.masked_text, finding.location)
        if key in seen:
            continue
        seen.add(key)
        result.append((file_id, finding))
    return result


def _overall_risk(findings: list[Finding]) -> str:
    if any(f.risk_level == "High" for f in findings):
        return "High"
    if any(f.risk_level == "Medium" for f in findings):
        return "Medium"
    if any(f.risk_level == "Low" for f in findings):
        return "Low"
    return "None"


def _update_job(job_id: str, status: str, progress: int, message: str) -> None:
    db = get_db()
    db.execute(
        "UPDATE scan_jobs SET status = ?, progress = ?, message = ?, updated_at = ? WHERE id = ?",
        (status, progress, message, now_iso(), job_id),
    )
    db.commit()


def _set_file_error(file_id: str, message: str) -> None:
    db = get_db()
    db.execute("UPDATE files SET error = ? WHERE id = ?", (message, file_id))
    db.commit()


def _audit(actor: str, action: str, target_type: str, target_id: str, metadata: dict) -> None:
    db = get_db()
    db.execute(
        """
        INSERT INTO audit_logs (id, actor, action, target_type, target_id, metadata, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (str(uuid.uuid4()), actor, action, target_type, target_id, json.dumps(metadata), now_iso()),
    )
