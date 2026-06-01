from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from app.db import get_db
from app.scanner import run_website_scan
from app.url_security import UnsafeUrlError, validate_public_url
from pii_scanner.detectors.base import Finding, Severity
from pii_scanner.scanners.web_scanner import _request_get


def test_website_check_creates_background_job(client, monkeypatch):
    submitted = []
    monkeypatch.setattr("app.routes.validate_public_url", lambda url: None)
    monkeypatch.setattr(
        "app.routes.submit_website_scan",
        lambda *args: submitted.append(args),
    )
    response = client.post(
        "/api/sites/check",
        json={
            "url": "https://www.example.edu.tw/",
            "mode": "site",
            "maxPages": 10,
            "maxDepth": 1,
            "useSitemap": True,
        },
    )
    assert response.status_code == 202
    assert submitted
    job = client.get(f"/api/jobs/{response.get_json()['jobId']}").get_json()
    assert job["status"] == "queued"
    assert job["files"][0]["extension"] == ".url"


def test_url_security_blocks_local_network():
    with pytest.raises(UnsafeUrlError):
        validate_public_url("http://127.0.0.1/admin")


def test_redirect_target_is_validated_before_following_request():
    response = MagicMock()
    response.status_code = 302
    response.headers = {"Location": "http://127.0.0.1/internal"}
    get = MagicMock(return_value=response)
    checked = []

    def validator(url):
        checked.append(url)
        if "127.0.0.1" in url:
            raise UnsafeUrlError("blocked")

    with pytest.raises(UnsafeUrlError), pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr("pii_scanner.scanners.web_scanner.requests.get", get)
        _request_get(
            "https://example.com/",
            headers={},
            timeout=1,
            verify_tls=True,
            url_validator=validator,
        )
    assert checked == ["https://example.com/", "http://127.0.0.1/internal"]
    assert get.call_count == 1


def test_website_job_stores_masked_result_without_raw_value(client, monkeypatch):
    app = client.application
    job_id = str(uuid.uuid4())
    file_id = str(uuid.uuid4())
    finding = Finding(
        detector="taiwan_id",
        category="taiwan_id",
        severity=Severity.CRITICAL,
        value="A123456789",
        masked="A********9",
        start=0,
        end=10,
        source="https://example.com/list",
    )
    monkeypatch.setattr("pii_scanner.scanners.web_scanner.scan_url", lambda *args, **kwargs: [finding])
    with app.app_context():
        db = get_db()
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            """
            INSERT INTO scan_jobs
            (id, actor, status, progress, message, file_count, total_size, created_at, updated_at)
            VALUES (?, 'anonymous', 'queued', 0, 'queued', 1, 0, ?, ?)
            """,
            (job_id, now, now),
        )
        db.execute(
            """
            INSERT INTO files
            (id, job_id, original_name, extension, size, sha256, status, created_at)
            VALUES (?, ?, 'https://example.com/list', '.url', 0, 'hash', 'queued', ?)
            """,
            (file_id, job_id, now),
        )
        db.commit()
        run_website_scan(job_id, file_id, "https://example.com/list", "url", 1, 0, False)
        stored = db.execute(
            "SELECT masked_text, location FROM findings WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        assert stored["masked_text"] == "A********9"
        assert "A123456789" not in str(dict(stored))


def test_admin_can_save_and_reload_whitelist(client, monkeypatch, tmp_path):
    import pii_scanner.whitelist.store as store

    path = tmp_path / "whitelist.json"
    monkeypatch.setattr(store, "WHITELIST_PATH", path)
    monkeypatch.setattr(store, "_cache_config", None)
    monkeypatch.setattr(store, "_cache_mtime", -2.0)
    response = client.put(
        "/api/admin/whitelist",
        json={
            "version": 1,
            "global_disabled_detectors": ["surname_name"],
            "ignore_words": ["public@example.com"],
            "domain_rules": [
                {
                    "domain": "tku.edu.tw",
                    "disabled_detectors": ["taiwan_address"],
                    "ignore_words": ["02-2621-5656"],
                }
            ],
        },
    )
    assert response.status_code == 200
    payload = client.get("/api/admin/whitelist").get_json()
    assert payload["config"]["ignore_words"] == ["public@example.com"]
    assert payload["config"]["domain_rules"][0]["domain"] == "tku.edu.tw"


def test_admin_whitelist_rejects_url_as_domain(client):
    response = client.put(
        "/api/admin/whitelist",
        json={"domain_rules": [{"domain": "https://tku.edu.tw/path"}]},
    )
    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_whitelist"


def test_website_job_applies_whitelist_before_persisting(client, monkeypatch):
    app = client.application
    job_id = str(uuid.uuid4())
    file_id = str(uuid.uuid4())
    finding = Finding(
        detector="email",
        category="email",
        severity=Severity.MEDIUM,
        value="public@example.com",
        masked="pu***@example.com",
        start=0,
        end=18,
        source="https://example.com/",
    )
    monkeypatch.setattr("pii_scanner.scanners.web_scanner.scan_url", lambda *args, **kwargs: [finding])
    monkeypatch.setattr("app.scanner.apply_whitelist", lambda findings: [])
    with app.app_context():
        db = get_db()
        now = datetime.now(timezone.utc).isoformat()
        db.execute(
            """
            INSERT INTO scan_jobs
            (id, actor, status, progress, message, file_count, total_size, created_at, updated_at)
            VALUES (?, 'anonymous', 'queued', 0, 'queued', 1, 0, ?, ?)
            """,
            (job_id, now, now),
        )
        db.execute(
            """
            INSERT INTO files
            (id, job_id, original_name, extension, size, sha256, status, created_at)
            VALUES (?, ?, 'https://example.com/', '.url', 0, 'hash', 'queued', ?)
            """,
            (file_id, job_id, now),
        )
        db.commit()
        run_website_scan(job_id, file_id, "https://example.com/", "url", 1, 0, False)
        count = db.execute(
            "SELECT COUNT(*) AS count FROM findings WHERE job_id = ?",
            (job_id,),
        ).fetchone()["count"]
        assert count == 0
