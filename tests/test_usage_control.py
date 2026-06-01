from __future__ import annotations

import io
import uuid
from datetime import datetime, timezone

from app.db import get_db
from app.usage_control import SERVICE_LANGUAGE, consume_usage


def test_estimate_api_returns_usage_before_upload(client):
    response = client.post(
        "/api/files/estimate",
        json={"files": [{"name": "名冊.txt", "size": 2500}, {"name": "掃描.png", "size": 800}]},
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["allowed"] is True
    assert payload["estimate"] == {
        "languageRecords": 4,
        "ocrPages": 1,
        "openAiTokens": 2825,
    }


def test_daily_user_job_limit_rejects_new_job_without_creating_it(client):
    client.put("/api/admin/settings", json={"dailyUserJobLimit": 1})
    first = client.post(
        "/api/files/check",
        data={"files": [(io.BytesIO(b"first"), "first.txt")]},
        content_type="multipart/form-data",
    )
    assert first.status_code == 202
    second = client.post(
        "/api/files/check",
        data={"files": [(io.BytesIO(b"second"), "second.txt")]},
        content_type="multipart/form-data",
    )
    assert second.status_code == 429
    assert second.get_json()["error"] == "quota_exceeded"


def test_kill_switch_avoids_disabled_service_quota_rejection(client):
    client.put(
        "/api/admin/settings",
        json={
            "monthlyLanguageRecordLimit": 0,
            "monthlyOpenAiTokenLimit": 0,
            "languagePiiEnabled": False,
            "openAiEnabled": False,
        },
    )
    response = client.post(
        "/api/files/estimate",
        json={"files": [{"name": "名冊.txt", "size": 2500}]},
    )
    assert response.status_code == 200
    assert response.get_json()["allowed"] is True


def test_admin_settings_reject_string_boolean_and_negative_quota(client):
    response = client.put("/api/admin/settings", json={"openAiEnabled": "false"})
    assert response.status_code == 400
    response = client.put("/api/admin/settings", json={"monthlyOpenAiTokenLimit": -1})
    assert response.status_code == 400


def test_admin_usage_summary_and_job_report_do_not_store_content(client):
    app = client.application
    job_id = str(uuid.uuid4())
    with app.app_context():
        db = get_db()
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            """
            INSERT INTO scan_jobs
            (id, actor, status, progress, message, file_count, total_size, created_at, updated_at)
            VALUES (?, 'anonymous', 'completed', 100, 'done', 0, 0, ?, ?)
            """,
            (job_id, now, now),
        )
        db.commit()
        consume_usage(
            job_id,
            "anonymous",
            SERVICE_LANGUAGE,
            2,
            "text_record",
            {"fileId": "file-1", "batch": 1},
        )

    usage = client.get("/api/admin/usage").get_json()
    assert usage["monthly"]["languageRecords"]["used"] == 2
    report = client.get(f"/api/jobs/{job_id}/report").get_json()
    assert report["aiUsage"] == [
        {
            "createdAt": report["aiUsage"][0]["createdAt"],
            "metadata": {"batch": 1, "fileId": "file-1"},
            "service": "language",
            "unitName": "text_record",
            "units": 2,
        }
    ]
    assert "content" not in str(report["aiUsage"]).lower()
