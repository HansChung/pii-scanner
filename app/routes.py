from __future__ import annotations

import json
import hashlib
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, Response, current_app, jsonify, request
from requests import RequestException

from .auth import admin_required, auth_configured, current_user, current_user_name, is_admin, login_required
from .azure_services import test_azure_ai_service
from .db import get_db, row_to_dict
from .scanner import (
    cancel_scan,
    cleanup_stale_uploads,
    create_file_hash,
    now_iso,
    submit_scan,
    submit_website_scan,
)
from .security import mime_matches_extension, normalize_extension, safe_filename, sniff_mime
from .secret_settings import (
    clear_azure_secret,
    public_azure_ai_config,
    update_azure_ai_config,
)
from .report_export import build_excel, build_pdf, collect_report
from .usage_control import effective_settings, estimate_files, job_usage, quota_check, usage_summary
from .url_security import UnsafeUrlError, validate_public_url
from pii_scanner.whitelist import WhitelistConfig, list_known_detectors, load_whitelist, save_whitelist

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
    cleanup_stale_uploads()
    files = request.files.getlist("files")
    if not files:
        return jsonify({"error": "missing_files", "message": "請選擇要查驗的檔案。"}), 400
    settings = effective_settings()
    actor = current_user_name()
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

        estimate = estimate_files(
            [
                {"extension": record["extension"], "size": Path(record["path"]).stat().st_size}
                for record in upload_records
            ]
        )
        quota_errors = quota_check(actor, estimate)
        if quota_errors:
            db.rollback()
            shutil.rmtree(upload_dir, ignore_errors=True)
            return (
                jsonify(
                    {
                        "error": "quota_exceeded",
                        "message": " ".join(quota_errors),
                        "estimate": estimate,
                    }
                ),
                429,
            )
        db.execute(
            """
            INSERT INTO scan_jobs
            (id, actor, status, progress, message, file_count, total_size, created_at, updated_at)
            VALUES (?, ?, 'queued', 0, '等待查驗', ?, ?, ?, ?)
            """,
            (job_id, actor, len(upload_records), total_size, now_iso(), now_iso()),
        )
        _audit(actor, "files_uploaded", "scan_job", job_id, {"fileCount": len(upload_records), "estimate": estimate})
        db.commit()
        submit_scan(job_id, upload_records)
        return jsonify({"jobId": job_id, "status": "queued"}), 202
    except Exception:
        db.rollback()
        for path in upload_dir.glob("*"):
            path.unlink(missing_ok=True)
        upload_dir.rmdir()
        raise


@api.post("/files/estimate")
@login_required
def estimate_upload():
    payload = request.get_json(silent=True) or {}
    files = payload.get("files", [])
    if not isinstance(files, list):
        return jsonify({"error": "invalid_files", "message": "files 必須是陣列。"}), 400
    settings = effective_settings()
    normalized = []
    errors = []
    if len(files) > settings["maxFilesPerUpload"]:
        errors.append(f"單次最多上傳 {settings['maxFilesPerUpload']} 個檔案。")
    for item in files:
        extension = normalize_extension(str(item.get("name", "")))
        size = max(0, int(item.get("size", 0)))
        if extension not in settings["allowedExtensions"]:
            errors.append(f"不支援的檔案格式：{extension or '未知'}")
        if size > settings["maxFileMb"] * 1024 * 1024:
            errors.append("檔案過大，請先分檔後重新上傳。")
        normalized.append({"extension": extension, "size": size})
    estimate = estimate_files(normalized)
    errors.extend(quota_check(current_user_name(), estimate))
    return jsonify({"estimate": estimate, "allowed": not errors, "errors": errors})


def _clean_patterns(value: object, limit: int = 20) -> list[str]:
    """正規化 include/exclude 規則：去空白、去重、限制數量與長度。"""
    if not isinstance(value, list):
        return []
    cleaned: list[str] = []
    for item in value:
        text = str(item).strip()
        if text and text not in cleaned:
            cleaned.append(text[:200])
        if len(cleaned) >= limit:
            break
    return cleaned


@api.post("/sites/check")
@login_required
def check_website():
    payload = request.get_json(silent=True) or {}
    url = str(payload.get("url", "")).strip()
    mode = str(payload.get("mode", "url"))
    if mode not in {"url", "site"}:
        return jsonify({"error": "invalid_mode", "message": "網站掃描模式不正確。"}), 400
    try:
        validate_public_url(url)
    except UnsafeUrlError as exc:
        return jsonify({"error": "unsafe_url", "message": str(exc)}), 400
    actor = current_user_name()
    quota_errors = quota_check(
        actor,
        {"ocrPages": 0, "languageRecords": 0, "openAiTokens": 0},
    )
    if quota_errors:
        return jsonify({"error": "quota_exceeded", "message": " ".join(quota_errors)}), 429
    try:
        max_pages = min(
            max(1, int(payload.get("maxPages", 10))),
            current_app.config["WEBSITE_SCAN_MAX_PAGES"],
        )
        max_depth = min(
            max(0, int(payload.get("maxDepth", 1))),
            current_app.config["WEBSITE_SCAN_MAX_DEPTH"],
        )
    except (TypeError, ValueError):
        return jsonify({"error": "invalid_limits", "message": "頁數與深度必須是整數。"}), 400
    use_sitemap = bool(payload.get("useSitemap", False))
    include_patterns = _clean_patterns(payload.get("includePatterns"))
    exclude_patterns = _clean_patterns(payload.get("excludePatterns"))
    job_id = str(uuid.uuid4())
    file_id = str(uuid.uuid4())
    created_at = now_iso()
    db = get_db()
    db.execute(
        """
        INSERT INTO scan_jobs
        (id, actor, status, progress, message, file_count, total_size, created_at, updated_at)
        VALUES (?, ?, 'queued', 0, '等待網站查驗', 1, 0, ?, ?)
        """,
        (job_id, actor, created_at, created_at),
    )
    db.execute(
        """
        INSERT INTO files
        (id, job_id, original_name, extension, size, sha256, status, created_at)
        VALUES (?, ?, ?, '.url', 0, ?, 'queued', ?)
        """,
        (file_id, job_id, url, hashlib.sha256(url.encode()).hexdigest(), created_at),
    )
    _audit(
        actor,
        "website_scan_created",
        "scan_job",
        job_id,
        {
            "mode": mode,
            "maxPages": max_pages,
            "maxDepth": max_depth,
            "useSitemap": use_sitemap,
            "includePatterns": include_patterns,
            "excludePatterns": exclude_patterns,
        },
    )
    db.commit()
    submit_website_scan(
        job_id, file_id, url, mode, max_pages, max_depth, use_sitemap,
        include_patterns, exclude_patterns,
    )
    return jsonify({"jobId": job_id, "status": "queued"}), 202


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
    raw_meta = job.pop("scan_meta", None)
    if raw_meta:
        try:
            job["scanMeta"] = json.loads(raw_meta)
        except (TypeError, ValueError):
            job["scanMeta"] = None
    else:
        job["scanMeta"] = None
    return jsonify(job)


@api.post("/jobs/<job_id>/cancel")
@login_required
def cancel_job(job_id: str):
    if not cancel_scan(job_id, current_user_name()):
        return jsonify({"error": "not_found", "message": "查無此任務。"}), 404
    return jsonify({"jobId": job_id, "status": "cancelling"})


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
    data = collect_report(job_id)
    if data is None:
        return jsonify({"error": "not_found", "message": "查無此任務。"}), 404
    return jsonify(data)


def _report_filename(job_id: str, extension: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"pii-report-{job_id[:8]}-{stamp}.{extension}"


@api.get("/jobs/<job_id>/report.xlsx")
@login_required
def report_excel(job_id: str):
    data = collect_report(job_id)
    if data is None:
        return jsonify({"error": "not_found", "message": "查無此任務。"}), 404
    payload = build_excel(data)
    return Response(
        payload,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            "Content-Disposition": f'attachment; filename="{_report_filename(job_id, "xlsx")}"'
        },
    )


@api.get("/jobs/<job_id>/report.pdf")
@login_required
def report_pdf(job_id: str):
    data = collect_report(job_id)
    if data is None:
        return jsonify({"error": "not_found", "message": "查無此任務。"}), 404
    payload = build_pdf(data)
    return Response(
        payload,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{_report_filename(job_id, "pdf")}"'
        },
    )


@api.get("/admin/settings")
@login_required
def get_settings():
    return jsonify(effective_settings())


@api.put("/admin/settings")
@admin_required
def put_settings():
    payload = request.get_json(silent=True) or {}
    allowed_keys = {
        "maxFileMb",
        "maxFilesPerUpload",
        "allowedExtensions",
        "highRiskThreshold",
        "dailyUserJobLimit",
        "monthlyOcrPageLimit",
        "monthlyLanguageRecordLimit",
        "monthlyOpenAiTokenLimit",
        "documentIntelligenceEnabled",
        "languagePiiEnabled",
        "openAiEnabled",
        "openAiEscalationOnly",
    }
    integer_keys = {
        "maxFileMb",
        "maxFilesPerUpload",
        "dailyUserJobLimit",
        "monthlyOcrPageLimit",
        "monthlyLanguageRecordLimit",
        "monthlyOpenAiTokenLimit",
    }
    boolean_keys = {
        "documentIntelligenceEnabled",
        "languagePiiEnabled",
        "openAiEnabled",
        "openAiEscalationOnly",
    }
    db = get_db()
    for key in allowed_keys:
        if key in payload:
            value = payload[key]
            if key in integer_keys and (not isinstance(value, int) or isinstance(value, bool) or value < 0):
                return jsonify({"error": "invalid_settings", "message": f"{key} 必須是非負整數。"}), 400
            if key in {"maxFileMb", "maxFilesPerUpload", "dailyUserJobLimit"} and value < 1:
                return jsonify({"error": "invalid_settings", "message": f"{key} 必須至少為 1。"}), 400
            if key in boolean_keys and not isinstance(value, bool):
                return jsonify({"error": "invalid_settings", "message": f"{key} 必須是布林值。"}), 400
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
    return jsonify(effective_settings())


@api.get("/admin/usage")
@admin_required
def get_usage_summary():
    return jsonify(usage_summary(current_user_name()))


@api.get("/admin/whitelist")
@admin_required
def get_whitelist():
    config = load_whitelist(force_reload=True)
    return jsonify({"config": config.to_dict(), "detectors": list_known_detectors()})


@api.put("/admin/whitelist")
@admin_required
def put_whitelist():
    payload = request.get_json(silent=True) or {}
    try:
        config = WhitelistConfig.from_dict(payload)
        _validate_whitelist(config)
        save_whitelist(config)
    except (TypeError, ValueError, KeyError) as exc:
        return jsonify({"error": "invalid_whitelist", "message": f"白名單格式錯誤：{exc}"}), 400
    except OSError as exc:
        return jsonify({"error": "whitelist_write_failed", "message": str(exc)}), 500
    _audit(current_user_name(), "whitelist_updated", "settings", "whitelist", {})
    get_db().commit()
    return jsonify({"config": config.to_dict(), "detectors": list_known_detectors()})


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


@api.post("/admin/azure-ai/test")
@admin_required
def test_azure_ai_settings():
    service = str((request.get_json(silent=True) or {}).get("service", ""))
    try:
        message = test_azure_ai_service(service)
    except ValueError as exc:
        return jsonify({"error": "invalid_settings", "message": str(exc)}), 400
    except (KeyError, RequestException, RuntimeError, TimeoutError):
        return (
            jsonify(
                {
                    "error": "azure_ai_connection_failed",
                    "message": "Azure AI 連線失敗，請確認 Endpoint、API key、API version 與服務權限。",
                }
            ),
            502,
        )
    _audit(current_user_name(), "azure_ai_connection_tested", "settings", service, {})
    get_db().commit()
    return jsonify({"service": service, "status": "ok", "message": message})


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


def _validate_whitelist(config: WhitelistConfig) -> None:
    known_detectors = set(list_known_detectors())
    unknown = set(config.global_disabled_detectors) - known_detectors
    for rule in config.domain_rules:
        if not rule.domain.strip() or "://" in rule.domain or "/" in rule.domain:
            raise ValueError("網域規則只能填寫網域，例如 tku.edu.tw。")
        unknown.update(set(rule.disabled_detectors) - known_detectors)
    if unknown:
        raise ValueError(f"不支援的偵測器：{', '.join(sorted(unknown))}")
