"""將 :class:`Finding` 清單轉成不同輸出格式。"""
from __future__ import annotations

import html as html_lib
import json
from collections import Counter
from datetime import datetime, timezone
from typing import Iterable, List, Optional

from ..detectors.base import Finding, Severity
from .source_label import (
    format_file_display_name,
    split_source_label,
    summarize_by_file,
    summarize_by_source,
)

SEVERITY_ORDER = {
    Severity.CRITICAL.value: 0,
    Severity.HIGH.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 3,
}

ANSI_COLORS = {
    "critical": "\033[1;41;97m",  # 紅底白字粗體
    "high": "\033[1;31m",
    "medium": "\033[1;33m",
    "low": "\033[1;34m",
    "reset": "\033[0m",
    "dim": "\033[2m",
    "bold": "\033[1m",
}


def summarize(findings: Iterable[Finding]) -> dict:
    findings = list(findings)
    severity_counter = Counter(f.severity.value for f in findings)
    category_counter = Counter(f.category for f in findings)
    detector_counter = Counter(f.detector for f in findings)
    sources = sorted({f.source for f in findings if f.source})
    return {
        "total": len(findings),
        "by_severity": dict(severity_counter),
        "by_category": dict(category_counter),
        "by_detector": dict(detector_counter),
        "sources": sources,
        "by_source": summarize_by_source(findings),
        "by_file": summarize_by_file(findings),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def findings_to_dict(
    findings: Iterable[Finding],
    meta: dict | None = None,
    scan_issues: Optional[List[dict]] = None,
) -> dict:
    findings = sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity.value, 9), f.source or "", f.start),
    )
    out = {
        "summary": summarize(findings),
        "findings": [f.to_dict() for f in findings],
    }
    if meta:
        out["meta"] = meta
    if scan_issues:
        out["scan_issues"] = scan_issues
    return out


def render_json(
    findings: Iterable[Finding],
    indent: int = 2,
    scan_issues: Optional[List[dict]] = None,
) -> str:
    return json.dumps(findings_to_dict(findings, scan_issues=scan_issues), ensure_ascii=False, indent=indent)


def render_terminal(findings: Iterable[Finding], use_color: bool = True) -> str:
    findings = list(findings)
    summary = summarize(findings)
    lines: List[str] = []

    def c(key: str) -> str:
        return ANSI_COLORS.get(key, "") if use_color else ""

    lines.append(f"{c('bold')}PII 掃描報告{c('reset')}")
    lines.append(f"  總命中數: {summary['total']}")
    if summary["by_severity"]:
        sev_parts = []
        for sev in ("critical", "high", "medium", "low"):
            if sev in summary["by_severity"]:
                sev_parts.append(f"{c(sev)}{sev}={summary['by_severity'][sev]}{c('reset')}")
        lines.append("  嚴重度: " + ", ".join(sev_parts))
    if summary["by_category"]:
        lines.append(
            "  類別: "
            + ", ".join(f"{k}={v}" for k, v in sorted(summary["by_category"].items()))
        )
    if summary.get("by_file"):
        lines.append("")
        lines.append(f"{c('bold')}依頁面 / 檔案摘要{c('reset')}")
        for row in summary["by_file"]:
            kind = row.get("kind_label") or ""
            name = row.get("display") or format_file_display_name(row["file"])
            prefix = f"[{kind}] " if kind else ""
            lines.append(
                f"  {c('bold')}{prefix}{name}{c('reset')} ({row['file']}) — {row['total']} 筆"
            )
            for loc in row["locations"]:
                lines.append(f"    · {loc['label']}: {loc['count']}")
    lines.append("")

    sorted_findings = sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity.value, 9), f.source or "", f.start),
    )
    for f in sorted_findings:
        src = f.source or "<inline>"
        parts = split_source_label(f.source)
        loc_hint = ""
        if parts["location"]:
            loc_hint = f" ({parts['location']})"
        sev = f.severity.value
        lines.append(
            f"{c(sev)}[{sev.upper()}]{c('reset')} "
            f"{c('bold')}{f.detector}{c('reset')} @ {src}{loc_hint}:{f.start}-{f.end}"
        )
        lines.append(f"  值      : {f.masked}  {c('dim')}(原值長度 {len(f.value)}){c('reset')}")
        lines.append(f"  類別    : {f.category}")
        if f.notes:
            lines.append(f"  說明    : {f.notes}")
        if f.context:
            lines.append(f"  上下文  : {c('dim')}{f.context}{c('reset')}")
        lines.append("")
    return "\n".join(lines)


HTML_HEAD = """<!doctype html>
<html lang="zh-Hant"><head>
<meta charset="utf-8">
<title>PII 掃描報告</title>
<style>
  body{font-family:-apple-system,"Segoe UI",Roboto,"PingFang TC","Microsoft JhengHei",sans-serif;
       margin:24px;background:#f7f7fb;color:#1f2330;}
  h1{margin:0 0 8px;}
  .summary{background:#fff;padding:16px 20px;border-radius:8px;
           box-shadow:0 1px 3px rgba(0,0,0,.08);margin-bottom:24px;}
  .pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;
        margin-right:6px;font-weight:600;}
  .pill.critical{background:#fde2e2;color:#a40000;}
  .pill.high{background:#ffe9d6;color:#aa4400;}
  .pill.medium{background:#fff5d1;color:#7a5500;}
  .pill.low{background:#dde9ff;color:#1d3d8a;}
  table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;
        overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.08);}
  th,td{padding:10px 12px;border-bottom:1px solid #eef;font-size:13px;vertical-align:top;}
  th{background:#f0f2fa;text-align:left;font-weight:600;}
  tr:last-child td{border-bottom:none;}
  td.value{font-family:ui-monospace,Menlo,Consolas,monospace;}
  td.context{color:#555;font-size:12px;max-width:380px;}
  .src{color:#666;font-size:12px;}
  .notes{color:#444;font-size:12px;}
</style></head>
<body>
<h1>PII 掃描報告</h1>
"""


def render_html(findings: Iterable[Finding], scan_issues: Optional[List[dict]] = None) -> str:
    findings = list(findings)
    summary = summarize(findings)
    sev_pills = " ".join(
        f'<span class="pill {k}">{html_lib.escape(k)}: {v}</span>'
        for k, v in summary["by_severity"].items()
    )
    cat_text = html_lib.escape(
        ", ".join(f"{k}={v}" for k, v in sorted(summary["by_category"].items()))
        or "無"
    )
    file_rows: List[str] = []
    for row in summary.get("by_file") or []:
        loc_text = "、".join(
            f"{html_lib.escape(loc['label'])} ({loc['count']})" for loc in row["locations"]
        )
        full = html_lib.escape(row["file"])
        file_rows.append(
            f"<tr><td>{html_lib.escape(row.get('kind_label') or '—')}</td>"
            f"<td><strong>{html_lib.escape(row.get('display') or format_file_display_name(row['file']))}</strong>"
            f'<div class="src">{full}</div></td>'
            f"<td>{row['total']}</td>"
            f"<td>{loc_text}</td></tr>"
        )
    issue_block = ""
    if scan_issues:
        issue_items = "".join(
            f"<li><code>{html_lib.escape(i['path'])}</code> — "
            f"{html_lib.escape(i['reason'])}</li>"
            for i in scan_issues
        )
        issue_block = (
            '<div class="summary" style="border-left:4px solid #aa4400">'
            "<strong>無法掃描的 URL / 檔案</strong>"
            f"<ul style=\"margin:8px 0 0;padding-left:20px\">{issue_items}</ul></div>"
        )
    rows: List[str] = []
    sorted_findings = sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity.value, 9), f.source or "", f.start),
    )
    for f in sorted_findings:
        parts = split_source_label(f.source)
        file_cell = html_lib.escape(format_file_display_name(parts["file"] or "<inline>"))
        if parts["file"] and format_file_display_name(parts["file"]) != parts["file"]:
            file_cell += f'<div class="src">{html_lib.escape(parts["file"])}</div>'
        loc_cell = html_lib.escape(parts["location"] or "—")
        rows.append(
            "<tr>"
            f'<td><span class="pill {f.severity.value}">{f.severity.value}</span></td>'
            f"<td>{html_lib.escape(f.detector)}"
            f'<div class="notes">{html_lib.escape(f.notes)}</div></td>'
            f"<td>{html_lib.escape(f.category)}</td>"
            f'<td class="value">{html_lib.escape(f.masked)}</td>'
            f"<td><strong>{file_cell}</strong>"
            f'<div class="src">{loc_cell}</div>'
            f'<div class="src">{f.start}-{f.end}</div></td>'
            f'<td class="context">{html_lib.escape(f.context)}</td>'
            "</tr>"
        )
    file_table = ""
    if file_rows:
        file_table = (
            '<h2 style="font-size:18px;margin:24px 0 8px">依頁面 / 檔案摘要</h2>'
            "<table><thead><tr>"
            "<th>類型</th><th>頁面 / 檔案</th><th>命中數</th><th>位置明細</th>"
            "</tr></thead><tbody>"
            + "\n".join(file_rows)
            + "</tbody></table>"
        )
    body = (
        issue_block
        + '<div class="summary">'
        f'<div><strong>產生時間：</strong>{html_lib.escape(summary["generated_at"])}</div>'
        f'<div><strong>總命中數：</strong>{summary["total"]}</div>'
        f'<div style="margin-top:8px">{sev_pills or "<em>無命中</em>"}</div>'
        f'<div style="margin-top:8px;color:#555">類別：{cat_text}</div>'
        "</div>"
        + file_table
        + "<table><thead><tr>"
        "<th>嚴重度</th><th>偵測器</th><th>類別</th>"
        "<th>命中值 (遮罩)</th><th>檔案 / 位置</th><th>上下文</th>"
        "</tr></thead><tbody>"
        + ("\n".join(rows) or "<tr><td colspan='6'>無命中</td></tr>")
        + "</tbody></table>"
    )
    return HTML_HEAD + body + "</body></html>"
