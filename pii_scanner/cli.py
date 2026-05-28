"""命令列工具入口。

用法範例::

  python -m pii_scanner.cli scan-text "我的手機 0912345678 身分證 A123456789"
  python -m pii_scanner.cli scan-file path/to/file.csv
  python -m pii_scanner.cli scan-dir ./data --format html -o report.html
  python -m pii_scanner.cli scan-url https://example.com
  python -m pii_scanner.cli scan-site https://example.com --max-pages 20

"""
from __future__ import annotations

import argparse
import sys
from typing import List

from .detectors.base import Finding
from .report import render_html, render_json, render_terminal
from .scanners.file_scanner import scan_directory, scan_file
from .scanners.text_scanner import scan_text


def _output(
    findings: List[Finding],
    fmt: str,
    out_path: str | None,
    scan_issues: list[dict] | None = None,
) -> None:
    if fmt == "json":
        content = render_json(findings, scan_issues=scan_issues)
    elif fmt == "html":
        content = render_html(findings, scan_issues=scan_issues)
    else:
        content = render_terminal(findings, use_color=(out_path is None and sys.stdout.isatty()))
        if scan_issues:
            content += "\n無法掃描的檔案:\n"
            for issue in scan_issues:
                content += f"  - {issue['path']}: {issue['reason']}\n"
    if out_path:
        with open(out_path, "w", encoding="utf-8") as fp:
            fp.write(content)
        print(f"已輸出至 {out_path}")
    else:
        print(content)


def _add_output_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--format", "-f", choices=("text", "json", "html"), default="text",
                   help="輸出格式 (預設 text)")
    p.add_argument("--output", "-o", help="輸出檔案 (預設輸出至 stdout)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pii-scanner",
        description="自動掃描網站、檔案、目錄中的個資 (PII)。",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_text = sub.add_parser("scan-text", help="掃描單一字串")
    p_text.add_argument("text", help="待掃描文字 (或 - 代表讀 stdin)")
    _add_output_args(p_text)

    p_file = sub.add_parser("scan-file", help="掃描單一檔案")
    p_file.add_argument("path", help="檔案路徑")
    _add_output_args(p_file)

    p_dir = sub.add_parser("scan-dir", help="遞迴掃描目錄")
    p_dir.add_argument("path", help="目錄路徑")
    p_dir.add_argument("--suffix", action="append",
                       help="僅掃描指定副檔名 (可重複，例如 --suffix .csv --suffix .txt)")
    _add_output_args(p_dir)

    p_url = sub.add_parser("scan-url", help="掃描單一 URL")
    p_url.add_argument("url")
    p_url.add_argument("--insecure", action="store_true", help="不驗證 TLS 憑證")
    _add_output_args(p_url)

    p_site = sub.add_parser("scan-site", help="遞迴爬取網站")
    p_site.add_argument("url")
    p_site.add_argument("--max-pages", type=int, default=30)
    p_site.add_argument("--max-depth", type=int, default=2)
    p_site.add_argument("--delay", type=float, default=0.5)
    p_site.add_argument("--no-robots", action="store_true", help="忽略 robots.txt")
    p_site.add_argument("--allow-cross-origin", action="store_true", help="允許跨網域連結")
    p_site.add_argument("--insecure", action="store_true", help="不驗證 TLS 憑證")
    _add_output_args(p_site)

    args = parser.parse_args(argv)

    if args.cmd == "scan-text":
        text = sys.stdin.read() if args.text == "-" else args.text
        findings = scan_text(text, source="<stdin>" if args.text == "-" else "<argv>")
        _output(findings, args.format, args.output)
    elif args.cmd == "scan-file":
        file_issues: list = []
        findings = scan_file(args.path, issues=file_issues)
        _output(
            findings,
            args.format,
            args.output,
            scan_issues=[i.to_dict() for i in file_issues],
        )
    elif args.cmd == "scan-dir":
        dir_issues: list = []
        findings = scan_directory(args.path, suffixes=args.suffix, issues=dir_issues)
        _output(
            findings,
            args.format,
            args.output,
            scan_issues=[i.to_dict() for i in dir_issues],
        )
    elif args.cmd == "scan-url":
        from .scanners.web_scanner import scan_url
        url_issues: list = []
        findings = scan_url(args.url, verify_tls=not args.insecure, issues=url_issues)
        _output(
            findings,
            args.format,
            args.output,
            scan_issues=[i.to_dict() for i in url_issues],
        )
    elif args.cmd == "scan-site":
        from .scanners.web_scanner import scan_site
        site_issues: list = []
        findings = scan_site(
            args.url,
            max_pages=args.max_pages,
            max_depth=args.max_depth,
            delay=args.delay,
            respect_robots=not args.no_robots,
            same_origin=not args.allow_cross_origin,
            verify_tls=not args.insecure,
            issues=site_issues,
        )
        _output(
            findings,
            args.format,
            args.output,
            scan_issues=[i.to_dict() for i in site_issues],
        )

    return 0 if not findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
