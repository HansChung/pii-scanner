"""驗證查驗報告的 PDF / Excel 匯出端點。"""
from __future__ import annotations

import io
import uuid
import zipfile
from datetime import datetime, timezone

from app.db import get_db
from app.report_export import build_excel, build_pdf, collect_report


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _seed_job(client) -> str:
    """在測試 DB 建立一個含發現與審核紀錄的完成任務，回傳 job_id。"""
    job_id = str(uuid.uuid4())
    file_id = str(uuid.uuid4())
    with client.application.app_context():
        db = get_db()
        db.execute(
            """
            INSERT INTO scan_jobs (id, actor, status, progress, message, risk_level, created_at, updated_at, completed_at)
            VALUES (?, ?, 'completed', 100, '查驗完成', 'High', ?, ?, ?)
            """,
            (job_id, "tester@example.com", _now(), _now(), _now()),
        )
        db.execute(
            """
            INSERT INTO files (id, job_id, original_name, extension, size, sha256, status, error, created_at)
            VALUES (?, ?, '公告.pdf', '.pdf', 1024, 'deadbeef', 'completed', NULL, ?)
            """,
            (file_id, job_id, _now()),
        )
        db.execute(
            """
            INSERT INTO findings
            (id, job_id, file_id, detector, category, risk_level, confidence, masked_text, location, recommendation, created_at)
            VALUES (?, ?, ?, 'taiwan_id', 'TaiwanNationalId', 'High', 0.9, 'A1******89', '第 1 頁', '請移除或遮罩。', ?)
            """,
            (str(uuid.uuid4()), job_id, file_id, _now()),
        )
        db.execute(
            """
            INSERT INTO reviews (id, job_id, decision, reviewer, note, created_at)
            VALUES (?, ?, 'needs_changes', '王小明', '請遮罩身分證', ?)
            """,
            (str(uuid.uuid4()), job_id, _now()),
        )
        db.commit()
    return job_id


def test_collect_report_aggregates_data(client):
    job_id = _seed_job(client)
    with client.application.app_context():
        report = collect_report(job_id)
    assert report is not None
    assert report["job"]["risk_level"] == "High"
    assert len(report["findings"]) == 1
    assert report["findings"][0]["category"] == "TaiwanNationalId"
    assert report["reviews"][0]["reviewer"] == "王小明"


def test_collect_report_missing_job(client):
    with client.application.app_context():
        assert collect_report(str(uuid.uuid4())) is None


def test_build_excel_is_valid_workbook(client):
    job_id = _seed_job(client)
    with client.application.app_context():
        payload = build_excel(collect_report(job_id))
    assert payload[:2] == b"PK"  # xlsx 是 zip 容器
    with zipfile.ZipFile(io.BytesIO(payload)) as zf:
        assert "xl/workbook.xml" in zf.namelist()


def test_build_pdf_has_signature(client):
    job_id = _seed_job(client)
    with client.application.app_context():
        payload = build_pdf(collect_report(job_id))
    assert payload[:4] == b"%PDF"
    assert len(payload) > 800


def test_report_pdf_endpoint(client):
    job_id = _seed_job(client)
    response = client.get(f"/api/jobs/{job_id}/report.pdf")
    assert response.status_code == 200
    assert response.mimetype == "application/pdf"
    assert response.data[:4] == b"%PDF"
    assert "attachment" in response.headers["Content-Disposition"]


def test_report_excel_endpoint(client):
    job_id = _seed_job(client)
    response = client.get(f"/api/jobs/{job_id}/report.xlsx")
    assert response.status_code == 200
    assert "spreadsheetml" in response.mimetype
    assert response.data[:2] == b"PK"


def test_report_export_missing_job_returns_404(client):
    missing = str(uuid.uuid4())
    assert client.get(f"/api/jobs/{missing}/report.pdf").status_code == 404
    assert client.get(f"/api/jobs/{missing}/report.xlsx").status_code == 404
