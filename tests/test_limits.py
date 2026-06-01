from __future__ import annotations

import io
import time


def test_rejects_too_many_files(client):
    response = client.post(
        "/api/files/check",
        data={
            "files": [
                (io.BytesIO(b"a"), "a.txt"),
                (io.BytesIO(b"b"), "b.txt"),
                (io.BytesIO(b"c"), "c.txt"),
            ]
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert response.get_json()["error"] == "too_many_files"


def test_rejects_unsupported_extension(client):
    response = client.post(
        "/api/files/check",
        data={"files": [(io.BytesIO(b"hello"), "a.exe")]},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert response.get_json()["error"] == "unsupported_file_type"


def test_rejects_oversized_file(client):
    response = client.post(
        "/api/files/check",
        data={"files": [(io.BytesIO(b"x" * (1024 * 1024 + 1)), "large.txt")]},
        content_type="multipart/form-data",
    )
    assert response.status_code == 413
    assert response.get_json()["message"] == "檔案過大，請先分檔後重新上傳。"


def test_scans_text_and_returns_masked_findings(client):
    response = client.post(
        "/api/files/check",
        data={"files": [(io.BytesIO("學生 A123456789 電話 0912-345-678".encode()), "list.txt")]},
        content_type="multipart/form-data",
    )
    assert response.status_code == 202
    job_id = response.get_json()["jobId"]
    for _ in range(30):
        job = client.get(f"/api/jobs/{job_id}").get_json()
        if job["status"] == "completed":
            break
        time.sleep(0.1)
    findings = client.get(f"/api/jobs/{job_id}/findings").get_json()["items"]
    assert findings
    assert all("A123456789" not in item["masked_text"] for item in findings)
    assert any(item["risk_level"] == "High" for item in findings)

