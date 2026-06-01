from __future__ import annotations

import hashlib
import json
import shutil
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
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
from .office_images import cleanup_embedded_images, extract_embedded_images
from .pii_rules import detect_with_rules
from .usage_control import (
    SERVICE_LANGUAGE,
    SERVICE_OCR,
    SERVICE_OPENAI,
    UsageLimitExceeded,
    consume_usage,
    effective_settings,
    estimate_language_records,
    estimate_ocr_pages,
    estimate_openai_tokens,
)

executor = ThreadPoolExecutor(max_workers=2)


class ScanCancelled(Exception):
    pass


class ScanTimedOut(Exception):
    pass


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
    job = db.execute("SELECT actor FROM scan_jobs WHERE id = ?", (job_id,)).fetchone()
    actor = job["actor"] if job else "anonymous"
    settings = effective_settings()
    temp_paths = [Path(record["path"]) for record in upload_records]
    deadline = time.monotonic() + current_app.config["JOB_TIMEOUT_SECONDS"]
    try:
        _ensure_active(job_id, deadline)
        _update_job(job_id, "processing", 5, "準備開始查驗")
        all_findings: list[tuple[str, Finding]] = []
        for index, record in enumerate(upload_records, start=1):
            _ensure_active(job_id, deadline)
            file_id = record["file_id"]
            path = Path(record["path"])
            extension = record["extension"]
            file_name = path.name
            base_progress = 5 + int((index - 1) / len(upload_records) * 85)
            span = max(1, int(85 / len(upload_records)))
            _update_file(file_id, "processing")
            _update_job(job_id, "processing", base_progress + int(span * 0.05), f"{file_name}：抽取文字")
            chunks = extract_text(path, extension)
            if (
                extension in {".pdf", ".jpg", ".jpeg", ".png"}
                and settings["documentIntelligenceEnabled"]
                and document_intelligence_enabled()
            ):
                try:
                    _ensure_active(job_id, deadline)
                    _update_job(
                        job_id,
                        "processing",
                        base_progress + int(span * 0.2),
                        f"{file_name}：等待 Azure AI 文件智慧服務 OCR",
                    )
                    consume_usage(
                        job_id,
                        actor,
                        SERVICE_OCR,
                        estimate_ocr_pages(path, extension),
                        "page",
                        {"fileId": file_id, "estimated": True},
                    )
                    ocr_chunks = extract_with_document_intelligence(
                        path,
                        heartbeat=lambda: _heartbeat(
                            job_id,
                            deadline,
                            f"{file_name}：等待 Azure AI 文件智慧服務 OCR",
                        ),
                    )
                    chunks.extend(ocr_chunks)
                except (ScanCancelled, ScanTimedOut):
                    raise
                except UsageLimitExceeded as exc:
                    _set_file_error(file_id, str(exc))
                except Exception as exc:
                    _set_file_error(file_id, f"OCR 失敗：{exc}")
            if (
                extension in {".docx", ".pptx", ".xlsx"}
                and settings["documentIntelligenceEnabled"]
                and document_intelligence_enabled()
            ):
                images = extract_embedded_images(
                    path,
                    extension,
                    max_images=current_app.config["OFFICE_OCR_MAX_IMAGES"],
                    max_image_bytes=current_app.config["OFFICE_OCR_MAX_IMAGE_MB"] * 1024 * 1024,
                )
                try:
                    for image_index, image in enumerate(images, start=1):
                        _ensure_active(job_id, deadline)
                        message = f"{file_name}：辨識 Office 內嵌圖片 {image_index}/{len(images)}"
                        _update_job(job_id, "processing", base_progress + int(span * 0.25), message)
                        consume_usage(
                            job_id,
                            actor,
                            SERVICE_OCR,
                            1,
                            "page",
                            {"fileId": file_id, "embeddedImage": True, "estimated": True},
                        )
                        for chunk in extract_with_document_intelligence(
                            image.path,
                            heartbeat=lambda: _heartbeat(job_id, deadline, message),
                        ):
                            chunks.append(
                                type(chunk)(
                                    text=chunk.text,
                                    location=f"{image.location} / {chunk.location}",
                                )
                            )
                except (ScanCancelled, ScanTimedOut):
                    raise
                except UsageLimitExceeded as exc:
                    _set_file_error(file_id, str(exc))
                except Exception as exc:
                    _set_file_error(file_id, f"Office 內嵌圖片 OCR 失敗：{exc}")
                finally:
                    cleanup_embedded_images(images)
            _update_job(
                job_id,
                "processing",
                base_progress + int(span * 0.45),
                f"{file_name}：執行本機個資規則",
            )
            file_findings_start = len(all_findings)
            for chunk in chunks:
                _ensure_active(job_id, deadline)
                all_findings.extend((file_id, finding) for finding in detect_with_rules(chunk.text, chunk.location))
            azure_batches = _text_batches(chunks, 5000)
            if settings["languagePiiEnabled"] and language_pii_enabled():
                for batch_index, batch in enumerate(azure_batches, start=1):
                    try:
                        _ensure_active(job_id, deadline)
                        _update_job(
                            job_id,
                            "processing",
                            base_progress + int(span * 0.6),
                            f"{file_name}：Azure Language PII {batch_index}/{len(azure_batches)}",
                        )
                        consume_usage(
                            job_id,
                            actor,
                            SERVICE_LANGUAGE,
                            estimate_language_records(batch.text),
                            "text_record",
                            {"fileId": file_id, "batch": batch_index},
                        )
                        all_findings.extend(
                            (file_id, finding)
                            for finding in detect_with_azure_language(batch.text, batch.location)
                        )
                    except (ScanCancelled, ScanTimedOut):
                        raise
                    except UsageLimitExceeded as exc:
                        _set_file_error(file_id, str(exc))
                        break
                    except Exception as exc:
                        _set_file_error(file_id, f"Azure Language PII 失敗：{exc}")
            should_run_openai = (
                not settings["openAiEscalationOnly"] or len(all_findings) > file_findings_start
            )
            if (
                settings["openAiEnabled"]
                and azure_openai_enabled()
                and azure_batches
                and should_run_openai
            ):
                try:
                    _ensure_active(job_id, deadline)
                    _update_job(
                        job_id,
                        "processing",
                        base_progress + int(span * 0.78),
                        f"{file_name}：等待 Azure OpenAI 語意風險判斷",
                    )
                    openai_text = "\n".join(batch.text for batch in azure_batches)[:6000]
                    consume_usage(
                        job_id,
                        actor,
                        SERVICE_OPENAI,
                        estimate_openai_tokens(openai_text),
                        "token",
                        {"fileId": file_id, "estimated": True},
                    )
                    all_findings.extend(
                        (file_id, finding)
                        for finding in detect_school_context_with_openai(openai_text, f"{file_name} 彙整文字")
                    )
                except (ScanCancelled, ScanTimedOut):
                    raise
                except UsageLimitExceeded as exc:
                    _set_file_error(file_id, str(exc))
                except Exception as exc:
                    _set_file_error(file_id, f"Azure OpenAI 失敗：{exc}")
            _update_file(file_id, "completed")
            _update_job(
                job_id,
                "processing",
                base_progress + span,
                f"{file_name}：檔案查驗完成",
            )

        _update_job(job_id, "processing", 95, "整理遮罩後風險結果")
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
    except ScanCancelled:
        _finish_stopped_job(job_id, "cancelled", "任務已取消", "scan_cancelled")
    except ScanTimedOut:
        _finish_stopped_job(job_id, "timed_out", "查驗逾時，已停止並清除暫存檔", "scan_timed_out")
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


def cancel_scan(job_id: str, actor: str) -> bool:
    db = get_db()
    row = db.execute("SELECT status FROM scan_jobs WHERE id = ?", (job_id,)).fetchone()
    if not row:
        return False
    if row["status"] in {"completed", "failed", "cancelled", "timed_out"}:
        return True
    db.execute(
        "UPDATE scan_jobs SET status = 'cancelling', message = ?, updated_at = ? WHERE id = ?",
        ("正在取消任務", now_iso(), job_id),
    )
    _audit(actor, "scan_cancel_requested", "scan_job", job_id, {})
    db.commit()
    return True


def cleanup_stale_uploads() -> int:
    upload_root = Path(current_app.config["TEMP_UPLOAD_DIR"])
    upload_root.mkdir(parents=True, exist_ok=True)
    threshold = datetime.now(timezone.utc) - timedelta(
        seconds=current_app.config["TEMP_UPLOAD_TTL_SECONDS"]
    )
    removed = 0
    for path in upload_root.iterdir():
        if not path.is_dir():
            continue
        modified = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        if modified >= threshold:
            continue
        shutil.rmtree(path, ignore_errors=True)
        removed += 1
        db = get_db()
        db.execute(
            """
            UPDATE scan_jobs
            SET status = 'timed_out', progress = 100, message = ?, updated_at = ?, completed_at = ?
            WHERE id = ? AND status IN ('queued', 'processing', 'cancelling')
            """,
            ("暫存檔逾期，任務已停止", now_iso(), now_iso(), path.name),
        )
        db.commit()
    return removed


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


def _update_file(file_id: str, status: str) -> None:
    db = get_db()
    db.execute("UPDATE files SET status = ? WHERE id = ?", (status, file_id))
    db.commit()


def _heartbeat(job_id: str, deadline: float, message: str) -> None:
    _ensure_active(job_id, deadline)
    db = get_db()
    db.execute(
        "UPDATE scan_jobs SET message = ?, updated_at = ? WHERE id = ?",
        (message, now_iso(), job_id),
    )
    db.commit()


def _text_batches(chunks, limit: int):
    batches = []
    texts = []
    locations = []
    size = 0
    for chunk in chunks:
        text = chunk.text.strip()
        if not text:
            continue
        if texts and size + len(text) + 1 > limit:
            batches.append(type(chunk)(text="\n".join(texts), location=_batch_location(locations)))
            texts = []
            locations = []
            size = 0
        while len(text) > limit:
            batches.append(type(chunk)(text=text[:limit], location=chunk.location))
            text = text[limit:]
        if text:
            texts.append(text)
            locations.append(chunk.location)
            size += len(text) + 1
    if texts:
        batches.append(type(chunks[0])(text="\n".join(texts), location=_batch_location(locations)))
    return batches


def _batch_location(locations: list[str]) -> str:
    if len(locations) == 1:
        return locations[0]
    return f"{locations[0]} 至 {locations[-1]}"


def _ensure_active(job_id: str, deadline: float) -> None:
    if time.monotonic() > deadline:
        raise ScanTimedOut()
    row = get_db().execute("SELECT status FROM scan_jobs WHERE id = ?", (job_id,)).fetchone()
    if row and row["status"] in {"cancelling", "cancelled"}:
        raise ScanCancelled()


def _finish_stopped_job(job_id: str, status: str, message: str, audit_action: str) -> None:
    db = get_db()
    db.execute(
        """
        UPDATE scan_jobs
        SET status = ?, progress = 100, message = ?, updated_at = ?, completed_at = ?
        WHERE id = ?
        """,
        (status, message, now_iso(), now_iso(), job_id),
    )
    db.execute("UPDATE files SET status = ? WHERE job_id = ?", (status, job_id))
    _audit("system", audit_action, "scan_job", job_id, {})
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
