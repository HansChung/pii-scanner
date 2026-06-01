from __future__ import annotations

import json
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, current_app, jsonify, request

from .auth import admin_required, auth_configured, current_user, current_user_name, is_admin, login_required
from .db import get_db, row_to_dict
from .scanner import create_file_hash, now_iso, submit_scan
from .security import mime_matches_extension, normalize_extension, safe_filename, sniff_mime
from .secret_settings import (
    clear_azure_secret,
    public_azure_ai_config,
    update_azure_ai_config,
)

api = Blueprint("api", __name__)


@api.get("/health")
def health():
    return jsonify({"status": "ok"})


@api.get("/auth/me")
def auth_me():
    user = current_user()
    return jsonify(
        {
            "authenticated": bool(user),
            "authRequired": current_app.config["AUTH_REQUIRED"],
            "authConfigured": auth_configured(),
            "isAdmin": is_admin(),
            "user": user,
        }
    )


@api.post("/files/check")
@login_required
def upload_and_check():
    files = request.files.getlist("files")
    if not files:
        return jsonify({"error": "missing_files", "message": "請選擇要查驗的檔案。"}), 400
    settings = _effective_settings()
    if len(files) > settings["maxFilesPerUpload"]:
        return (
            jsonify(
                {
                    "error": "too_many_files",
                    "message": f"單次最多上傳 {settings['maxFilesPerUpload']} 個檔案。",
                }
            ),
            400,
        )

    db = get_db()
    job_id = str(uuid.uuid4())
    upload_dir = Path(current_app.config["TEMP_UPLOAD_DIR"]) / job_id
    upload_dir.mkdir(parents=True, exist_ok=True)
    upload_records: list[dict[str, str]] = []
    total_size = 0
    try:
        for storage in files:
            if not storage.filename:
                return jsonify({"error": "invalid_file", "message": "檔名不可為空。"}), 400
            extension = normalize_extension(storage.filename)
            if extension not in settings["allowedExtensions"]:
                shutil.rmtree(upload_dir, ignore_errors=True)
                return (
                    jsonify(
                        {
                            "error": "unsupported_file_type",
                            "message": f"不支援的檔案格式：{extension}",
                        }
                    ),
                    400,
                )
            file_id = str(uuid.uuid4())
            destination = upload_dir / f"{file_id}-{safe_filename(storage.filename)}"
            storage.save(destination)
            size = destination.stat().st_size
            if size > settings["maxFileMb"] * 1024 * 1024:
                shutil.rmtree(upload_dir, ignore_errors=True)
                return (
                    jsonify(
                        {
                            "error": "file_too_large",
                            "message": "檔案過大，請先分檔後重新上傳。",
                            "filename": storage.filename,
                            "maxFileMb": settings["maxFileMb"],
                        }
                    ),
                    413,
                )
            mime = sniff_mime(destination, storage.mimetype or "")
            if not mime_matches_extension(extension, mime):
                shutil.rmtree(upload_dir, ignore_errors=True)
                return (
                    jsonify(
                        {
                            "error": "mime_type_mismatch",
                            "message": f"檔案內容與副檔名不符：{storage.filename}",
                            "detectedMimeType": mime,
                        }
                    ),
                    400,
                )
            sha256 = create_file_hash(destination)
            total_size += size
            db.execute(
                """
                INSERT INTO files
                (id, job_id, original_name, extension, size, sha256, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 'queued', ?)
                """,
                (file_id, job_id, storage.filename, extension, size, sha256, now_iso()),
            )
            upload_records.append(
                {
                    "file_id": file_id,
                    "path": str(destination),
                    "extension": extension,
                }
            )

        db.execute(
            """
            INSERT INTO scan_jobs
            (id, status, progress, message, file_count, total_size, created_at, updated_at)
            VALUES (?, 'queued', 0, '等待查驗', ?, ?, ?, ?)
            """,
            (job_id, len(upload_records), total_size, now_iso(), now_iso()),
        )
        _audit(current_user_name(), "files_uploaded", "scan_job", job_id, {"fileCount": len(upload_records)})
        db.commit()
        submit_scan(job_id, upload_records)
        return jsonify({"jobId": job_id, "status": "queued"}), 202
    except Exception:
        db.rollback()
        for path in upload_dir.glob("*"):
            path.unlink(missing_ok=True)
        upload_dir.rmdir()
        raise


@api.get("/jobs/<job_id>")
@login_required
def get_job(job_id: str):
    db = get_db()
    job = row_to_dict(db.execute("SELECT * FROM scan_jobs WHERE id = ?", (job_id,)).fetchone())
    if not job:
        return jsonify({"error": "not_found", "message": "查無此任務。"}), 404
    files = [
        dict(row)
        for row in db.execute(
            "SELECT id, original_name, extension, size, sha256, status, error FROM files WHERE job_id = ?",
            (job_id,),
        ).fetchall()
    ]
    job["files"] = files
    return jsonify(job)


@api.get("/jobs/<job_id>/findings")
@login_required
def get_findings(job_id: str):
    db = get_db()
    if not db.execute("SELECT 1 FROM scan_jobs WHERE id = ?", (job_id,)).fetchone():
        return jsonify({"error": "not_found", "message": "查無此任務。"}), 404
    rows = db.execute(
        """
        SELECT findings.*, files.original_name
        FROM findings
        JOIN files ON files.id = findings.file_id
        WHERE findings.job_id = ?
        ORDER BY
          CASE findings.risk_level WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END,
          findings.created_at
        """,
        (job_id,),
    ).fetchall()
    return jsonify({"items": [dict(row) for row in rows]})


@api.post("/jobs/<job_id>/review")
@login_required
def review_job(job_id: str):
    payload = request.get_json(silent=True) or {}
    decision = payload.get("decision")
    if decision not in {"approved", "needs_changes", "false_positive", "approved_after_redaction"}:
        return jsonify({"error": "invalid_decision", "message": "審核決策不正確。"}), 400
    reviewer = current_user_name()
    note = str(payload.get("note") or "")
    db = get_db()
    if not db.execute("SELECT 1 FROM scan_jobs WHERE id = ?", (job_id,)).fetchone():
        return jsonify({"error": "not_found", "message": "查無此任務。"}), 404
    review_id = str(uuid.uuid4())
    db.execute(
        """
        INSERT INTO reviews (id, job_id, decision, reviewer, note, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (review_id, job_id, decision, reviewer, note, now_iso()),
    )
    _audit(reviewer, "review_submitted", "scan_job", job_id, {"decision": decision})
    db.commit()
    return jsonify({"reviewId": review_id, "status": "saved"})


@api.get("/jobs/<job_id>/report")
@login_required
def report(job_id: str):
    db = get_db()
    job = row_to_dict(db.execute("SELECT * FROM scan_jobs WHERE id = ?", (job_id,)).fetchone())
    if not job:
        return jsonify({"error": "not_found", "message": "查無此任務。"}), 404
    findings = [
        dict(row)
        for row in db.execute(
            """
            SELECT files.original_name, findings.category, findings.risk_level, findings.confidence,
                   findings.masked_text, findings.location, findings.recommendation, findings.detector
            FROM findings
            JOIN files ON files.id = findings.file_id
            WHERE findings.job_id = ?
            ORDER BY findings.risk_level, files.original_name
            """,
            (job_id,),
        ).fetchall()
    ]
    reviews = [
        dict(row)
        for row in db.execute(
            "SELECT decision, reviewer, note, created_at FROM reviews WHERE job_id = ? ORDER BY created_at",
            (job_id,),
        ).fetchall()
    ]
    return jsonify({"job": job, "findings": findings, "reviews": reviews})


@api.get("/admin/settings")
@login_required
def get_settings():
    return jsonify(_effective_settings())


@api.put("/admin/settings")
@admin_required
def put_settings():
    payload = request.get_json(silent=True) or {}
    allowed_keys = {"maxFileMb", "maxFilesPerUpload", "allowedExtensions", "highRiskThreshold"}
    db = get_db()
    for key in allowed_keys:
        if key in payload:
            value = payload[key]
            if key == "allowedExtensions":
                if not isinstance(value, list):
                    return jsonify({"error": "invalid_settings", "message": "allowedExtensions 必須是陣列。"}), 400
                normalized = sorted({str(item).lower() for item in value if str(item).startswith(".")})
                value = normalized
            db.execute(
                """
                INSERT INTO settings (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, json.dumps(value, ensure_ascii=False)),
            )
    _audit(current_user_name(), "settings_updated", "settings", "global", {})
    db.commit()
    return jsonify(_effective_settings())


@api.get("/admin/azure-ai")
@admin_required
def get_azure_ai_settings():
    return jsonify(public_azure_ai_config())


@api.put("/admin/azure-ai")
@admin_required
def put_azure_ai_settings():
    payload = request.get_json(silent=True) or {}
    clear_secrets = payload.pop("clearSecrets", [])
    if not isinstance(clear_secrets, list):
        return jsonify({"error": "invalid_settings", "message": "clearSecrets 必須是陣列。"}), 400
    update_azure_ai_config(payload)
    for name in clear_secrets:
        clear_azure_secret(str(name))
    _audit(current_user_name(), "azure_ai_settings_updated", "settings", "azure_ai", {})
    get_db().commit()
    return jsonify(public_azure_ai_config())


def _effective_settings() -> dict:
    db = get_db()
    rows = db.execute("SELECT key, value FROM settings").fetchall()
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
    }


def _audit(actor: str, action: str, target_type: str, target_id: str, metadata: dict) -> None:
    db = get_db()
    db.execute(
        """
        INSERT INTO audit_logs (id, actor, action, target_type, target_id, metadata, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(uuid.uuid4()),
            actor,
            action,
            target_type,
            target_id,
            json.dumps(metadata, ensure_ascii=False),
            datetime.now(timezone.utc).isoformat(),
        ),
    )
