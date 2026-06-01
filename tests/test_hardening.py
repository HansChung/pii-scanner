from __future__ import annotations

import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZipFile

from app.db import get_db
from app.models import ExtractedText
from app.office_images import cleanup_embedded_images, extract_embedded_images
from app.pii_rules import detect_with_rules, validate_taiwan_id
from app.scanner import ScanTimedOut, _ensure_active, _text_batches, cleanup_stale_uploads, run_scan


def test_taiwan_id_requires_valid_checksum():
    assert validate_taiwan_id("A123456789") is True
    assert validate_taiwan_id("A123456788") is False
    findings = detect_with_rules("正確 A123456789 錯誤 A123456788", "測試")
    assert [finding.category for finding in findings].count("TaiwanNationalId") == 1


def test_extracts_office_embedded_images(tmp_path: Path):
    office_path = tmp_path / "sample.docx"
    with ZipFile(office_path, "w") as archive:
        archive.writestr("word/media/image1.png", b"\x89PNG\r\n\x1a\nfake")
        archive.writestr("word/document.xml", "<document />")
    images = extract_embedded_images(
        office_path,
        ".docx",
        max_images=5,
        max_image_bytes=1024,
    )
    assert len(images) == 1
    assert images[0].path.exists()
    assert "image1.png" in images[0].location
    cleanup_embedded_images(images)
    assert not images[0].path.parent.exists()


def test_cleanup_stale_uploads_marks_job_timed_out(client):
    app = client.application
    app.config["TEMP_UPLOAD_TTL_SECONDS"] = 1
    job_id = str(uuid.uuid4())
    upload_dir = Path(app.config["TEMP_UPLOAD_DIR"]) / job_id
    upload_dir.mkdir(parents=True)
    (upload_dir / "source.txt").write_text("temporary")
    old = time.time() - 10
    os.utime(upload_dir, (old, old))
    with app.app_context():
        db = get_db()
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            """
            INSERT INTO scan_jobs
            (id, status, progress, message, file_count, total_size, created_at, updated_at)
            VALUES (?, 'processing', 10, 'scan', 1, 9, ?, ?)
            """,
            (job_id, now, now),
        )
        db.commit()
        assert cleanup_stale_uploads() == 1
        row = db.execute("SELECT status FROM scan_jobs WHERE id = ?", (job_id,)).fetchone()
        assert row["status"] == "timed_out"
    assert not upload_dir.exists()


def test_cancel_job_api_updates_status(client):
    app = client.application
    job_id = str(uuid.uuid4())
    with app.app_context():
        db = get_db()
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            """
            INSERT INTO scan_jobs
            (id, status, progress, message, file_count, total_size, created_at, updated_at)
            VALUES (?, 'queued', 0, 'queued', 0, 0, ?, ?)
            """,
            (job_id, now, now),
        )
        db.commit()
    response = client.post(f"/api/jobs/{job_id}/cancel")
    assert response.status_code == 200
    with app.app_context():
        row = get_db().execute("SELECT status FROM scan_jobs WHERE id = ?", (job_id,)).fetchone()
        assert row["status"] == "cancelling"


def test_timeout_check_stops_scan():
    try:
        _ensure_active("missing-job", time.monotonic() - 1)
    except ScanTimedOut:
        pass
    else:
        raise AssertionError("expired deadline must stop the scan")


def test_scanner_ocr_checks_embedded_office_image(client, monkeypatch):
    app = client.application
    job_id = str(uuid.uuid4())
    file_id = str(uuid.uuid4())
    upload_dir = Path(app.config["TEMP_UPLOAD_DIR"]) / job_id
    upload_dir.mkdir(parents=True)
    office_path = upload_dir / "sample.docx"
    with ZipFile(office_path, "w") as archive:
        archive.writestr("word/media/image1.png", b"\x89PNG\r\n\x1a\nfake")
        archive.writestr("word/document.xml", "<document />")

    monkeypatch.setattr("app.scanner.extract_text", lambda path, extension: [])
    monkeypatch.setattr("app.scanner.document_intelligence_enabled", lambda: True)
    monkeypatch.setattr(
        "app.scanner.extract_with_document_intelligence",
        lambda path, heartbeat=None: [ExtractedText(text="身分證 A123456789", location="OCR")],
    )

    with app.app_context():
        db = get_db()
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            """
            INSERT INTO scan_jobs
            (id, status, progress, message, file_count, total_size, created_at, updated_at)
            VALUES (?, 'queued', 0, 'queued', 1, ?, ?, ?)
            """,
            (job_id, office_path.stat().st_size, now, now),
        )
        db.execute(
            """
            INSERT INTO files
            (id, job_id, original_name, extension, size, sha256, status, created_at)
            VALUES (?, ?, 'sample.docx', '.docx', ?, 'hash', 'queued', ?)
            """,
            (file_id, job_id, office_path.stat().st_size, now),
        )
        db.commit()
        run_scan(job_id, [{"file_id": file_id, "path": str(office_path), "extension": ".docx"}])
        findings = db.execute(
            "SELECT category, location FROM findings WHERE job_id = ?",
            (job_id,),
        ).fetchall()
        assert any(row["category"] == "TaiwanNationalId" for row in findings)
        assert any("內嵌圖片" in row["location"] for row in findings)
    assert not upload_dir.exists()


def test_text_batches_reduce_external_ai_requests_without_exceeding_limit():
    chunks = [
        ExtractedText(text="第一列資料", location="工作表 名冊 第 1 列"),
        ExtractedText(text="第二列資料", location="工作表 名冊 第 2 列"),
        ExtractedText(text="第三列資料", location="工作表 名冊 第 3 列"),
    ]
    batches = _text_batches(chunks, 30)
    assert len(batches) == 1
    assert "第一列資料" in batches[0].text
    assert "第三列資料" in batches[0].text
    assert batches[0].location == "工作表 名冊 第 1 列 至 工作表 名冊 第 3 列"


def test_scanner_batches_external_ai_requests_per_file(client, monkeypatch):
    app = client.application
    job_id = str(uuid.uuid4())
    file_id = str(uuid.uuid4())
    upload_dir = Path(app.config["TEMP_UPLOAD_DIR"]) / job_id
    upload_dir.mkdir(parents=True)
    source_path = upload_dir / "sample.xlsx"
    source_path.write_bytes(b"placeholder")
    language_calls = []
    openai_calls = []

    monkeypatch.setattr(
        "app.scanner.extract_text",
        lambda path, extension: [
            ExtractedText(text="第一列 王小明", location="工作表 名冊 第 1 列"),
            ExtractedText(text="第二列 A123456789", location="工作表 名冊 第 2 列"),
            ExtractedText(text="第三列 0912345678", location="工作表 名冊 第 3 列"),
        ],
    )
    monkeypatch.setattr("app.scanner.document_intelligence_enabled", lambda: False)
    monkeypatch.setattr("app.scanner.language_pii_enabled", lambda: True)
    monkeypatch.setattr("app.scanner.azure_openai_enabled", lambda: True)
    monkeypatch.setattr(
        "app.scanner.detect_with_azure_language",
        lambda text, location: language_calls.append((text, location)) or [],
    )
    monkeypatch.setattr(
        "app.scanner.detect_school_context_with_openai",
        lambda text, location: openai_calls.append((text, location)) or [],
    )

    with app.app_context():
        db = get_db()
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            """
            INSERT INTO scan_jobs
            (id, status, progress, message, file_count, total_size, created_at, updated_at)
            VALUES (?, 'queued', 0, 'queued', 1, ?, ?, ?)
            """,
            (job_id, source_path.stat().st_size, now, now),
        )
        db.execute(
            """
            INSERT INTO files
            (id, job_id, original_name, extension, size, sha256, status, created_at)
            VALUES (?, ?, 'sample.xlsx', '.xlsx', ?, 'hash', 'queued', ?)
            """,
            (file_id, job_id, source_path.stat().st_size, now),
        )
        db.commit()
        run_scan(job_id, [{"file_id": file_id, "path": str(source_path), "extension": ".xlsx"}])
        job = db.execute("SELECT status, progress FROM scan_jobs WHERE id = ?", (job_id,)).fetchone()
        file = db.execute("SELECT status FROM files WHERE id = ?", (file_id,)).fetchone()

    assert len(language_calls) == 1
    assert len(openai_calls) == 1
    assert job["status"] == "completed"
    assert job["progress"] == 100
    assert file["status"] == "completed"
