"""個資 (PII) 自動掃描套件。

提供文字、檔案、目錄與網站爬蟲掃描，內建台灣常見個資格式偵測。
"""
from .detectors import ALL_DETECTORS, Finding, detect_in_text
from .scanners.text_scanner import scan_text
from .scanners.file_scanner import scan_file, scan_directory
from .scanners.web_scanner import scan_url, scan_site

__version__ = "0.1.0"

__all__ = [
    "ALL_DETECTORS",
    "Finding",
    "detect_in_text",
    "scan_text",
    "scan_file",
    "scan_directory",
    "scan_url",
    "scan_site",
    "__version__",
]
