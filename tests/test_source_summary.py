"""報告來源標籤與依檔案彙總測試。"""

from pii_scanner.detectors.base import Finding, Severity
from pii_scanner.report.renderer import summarize
from pii_scanner.report.source_label import (
    split_source_label,
    summarize_by_file,
    summarize_by_source,
)
from pii_scanner.scanners.file_scanner import scan_directory, scan_file
from pii_scanner.scanners.scan_issue import ScanIssue


def _finding(source: str) -> Finding:
    return Finding(
        detector="taiwan_mobile",
        category="phone",
        severity=Severity.HIGH,
        value="0912345678",
        masked="0*******78",
        start=0,
        end=10,
        source=source,
    )


def test_split_source_label_with_sheet():
    parts = split_source_label("report.xlsx#學生名單")
    assert parts["file"] == "report.xlsx"
    assert parts["location"] == "學生名單"


def test_split_source_label_pdf_page():
    parts = split_source_label("report.pdf#page=2")
    assert parts["file"] == "report.pdf"
    assert parts["location"] == "page=2"


def test_summarize_by_file_groups_locations():
    findings = [
        _finding("data.xlsx#Sheet1"),
        _finding("data.xlsx#Sheet1"),
        _finding("data.xlsx#Sheet2"),
        _finding("/tmp/note.txt"),
    ]
    rows = summarize_by_file(findings)
    assert rows[0]["file"] == "data.xlsx"
    assert rows[0]["total"] == 3
    assert len(rows[0]["locations"]) == 2


def test_summarize_includes_by_file():
    summary = summarize([_finding("a.pdf#page=1")])
    assert summary["by_source"]["a.pdf#page=1"] == 1
    assert summary["by_file"][0]["file"] == "a.pdf"


def test_scan_directory_collects_issues(tmp_path):
    bad = tmp_path / "broken.xlsx"
    bad.write_bytes(b"not excel")
    good = tmp_path / "ok.txt"
    good.write_text("手機 0912345678", encoding="utf-8")

    issues: list[ScanIssue] = []
    findings = scan_directory(tmp_path, issues=issues)

    assert any(f.detector == "taiwan_mobile" for f in findings)
    assert any(i.path.endswith("broken.xlsx") for i in issues)
    assert not any(i.path.endswith("ok.txt") for i in issues)


def test_scan_file_issue_on_unreadable_document(tmp_path):
    p = tmp_path / "bad.xlsx"
    p.write_bytes(b"not a real xlsx")
    issues: list[ScanIssue] = []
    findings = scan_file(p, issues=issues)
    assert findings == []
    assert len(issues) == 1
    assert "bad.xlsx" in issues[0].path
