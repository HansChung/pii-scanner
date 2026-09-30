"""任務存取權限：只有建立者本人或 ADMIN_EMAILS 明列的管理者能讀取／操作任務。"""
from __future__ import annotations

import io
import uuid
from datetime import datetime, timezone

import pytest

from app import create_app
from app.db import get_db

OWNER = "owner@example.edu.tw"
OTHER = "other@example.edu.tw"
ADMIN = "admin@example.edu.tw"

JOB_READ_PATHS = [
    "/api/jobs/{job_id}",
    "/api/jobs/{job_id}/findings",
    "/api/jobs/{job_id}/report",
    "/api/jobs/{job_id}/report.xlsx",
    "/api/jobs/{job_id}/report.pdf",
]


def _make_app(monkeypatch, tmp_path, admin_emails: str):
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("TEMP_UPLOAD_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("AUTH_REQUIRED", "true")
    monkeypatch.setenv("ADMIN_EMAILS", admin_emails)
    app = create_app()
    app.config.update(TESTING=True)
    return app


def _insert_job(app, actor: str, status: str = "completed") -> str:
    job_id = str(uuid.uuid4())
    file_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    with app.app_context():
        db = get_db()
        db.execute(
            """
            INSERT INTO scan_jobs
            (id, actor, status, progress, message, file_count, total_size, risk_level,
             created_at, updated_at)
            VALUES (?, ?, ?, 100, '查驗完成', 1, 10, 'High', ?, ?)
            """,
            (job_id, actor, status, now, now),
        )
        db.execute(
            """
            INSERT INTO files (id, job_id, original_name, extension, size, sha256, status, created_at)
            VALUES (?, ?, '名冊.xlsx', '.xlsx', 10, 'hash', 'completed', ?)
            """,
            (file_id, job_id, now),
        )
        db.execute(
            """
            INSERT INTO findings
            (id, job_id, file_id, detector, category, risk_level, confidence, masked_text,
             location, recommendation, created_at)
            VALUES (?, ?, ?, 'taiwan_id', 'TaiwanNationalId', 'High', 0.9, 'A1******89',
                    '工作表 名冊 第 2 列', '請移除', ?)
            """,
            (str(uuid.uuid4()), job_id, file_id, now),
        )
        db.commit()
    return job_id


def _login(client, email: str) -> None:
    with client.session_transaction() as session:
        session["user"] = {"name": email, "email": email, "tenantId": "t", "objectId": email}


@pytest.fixture()
def app(monkeypatch, tmp_path):
    return _make_app(monkeypatch, tmp_path, ADMIN)


def test_owner_can_access_own_job(app):
    job_id = _insert_job(app, OWNER)
    with app.test_client() as client:
        _login(client, OWNER)
        for path in JOB_READ_PATHS:
            assert client.get(path.format(job_id=job_id)).status_code == 200, path
        assert client.get(f"/api/jobs/{job_id}/findings").get_json()["items"]
        review = client.post(f"/api/jobs/{job_id}/review", json={"decision": "approved"})
        assert review.status_code == 200
        assert client.post(f"/api/jobs/{job_id}/cancel").status_code == 200


def test_other_user_gets_not_found_for_every_job_endpoint(app):
    job_id = _insert_job(app, OWNER, status="processing")
    with app.test_client() as client:
        _login(client, OTHER)
        for path in JOB_READ_PATHS:
            response = client.get(path.format(job_id=job_id))
            assert response.status_code == 404, path
            assert "A1******89" not in response.get_data(as_text=True)
        assert client.post(
            f"/api/jobs/{job_id}/review", json={"decision": "approved"}
        ).status_code == 404
        assert client.post(f"/api/jobs/{job_id}/cancel").status_code == 404

    with app.app_context():
        db = get_db()
        status = db.execute("SELECT status FROM scan_jobs WHERE id = ?", (job_id,)).fetchone()
        assert status["status"] == "processing"  # 別人無法取消
        assert not db.execute("SELECT 1 FROM reviews WHERE job_id = ?", (job_id,)).fetchone()
        denied = db.execute(
            "SELECT actor FROM audit_logs WHERE action = 'job_access_denied' AND target_id = ?",
            (job_id,),
        ).fetchall()
        assert denied and all(row["actor"] == OTHER for row in denied)


def test_owner_match_ignores_email_case(app):
    job_id = _insert_job(app, OWNER)
    with app.test_client() as client:
        _login(client, OWNER.upper())
        assert client.get(f"/api/jobs/{job_id}").status_code == 200


def test_listed_admin_can_access_any_job(app):
    job_id = _insert_job(app, OWNER)
    with app.test_client() as client:
        _login(client, ADMIN)
        for path in JOB_READ_PATHS:
            assert client.get(path.format(job_id=job_id)).status_code == 200, path


def test_without_admin_emails_other_users_still_blocked(monkeypatch, tmp_path):
    # 未設定 ADMIN_EMAILS 時所有登入者都能進管理後台，但仍不能讀別人的任務
    app = _make_app(monkeypatch, tmp_path, "")
    job_id = _insert_job(app, OWNER)
    with app.test_client() as client:
        _login(client, OTHER)
        assert client.get("/api/auth/me").get_json()["isAdmin"] is True
        assert client.get(f"/api/jobs/{job_id}").status_code == 404


def test_anonymous_request_is_rejected(app):
    job_id = _insert_job(app, OWNER)
    with app.test_client() as client:
        assert client.get(f"/api/jobs/{job_id}").status_code == 401


def test_uploaded_job_is_owned_by_uploader(app):
    with app.test_client() as client:
        _login(client, OWNER)
        response = client.post(
            "/api/files/check",
            data={"files": [(io.BytesIO("手機 0912345678".encode()), "a.txt")]},
            content_type="multipart/form-data",
        )
        assert response.status_code == 202
        job_id = response.get_json()["jobId"]
        assert client.get(f"/api/jobs/{job_id}").status_code == 200
        _login(client, OTHER)
        assert client.get(f"/api/jobs/{job_id}").status_code == 404
