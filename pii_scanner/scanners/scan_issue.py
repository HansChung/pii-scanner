"""掃描過程中的非命中問題（無法讀取、無法解析等）。"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanIssue:
    """單一檔案掃描失敗紀錄。"""

    path: str
    reason: str

    def to_dict(self) -> dict:
        return {"path": self.path, "reason": self.reason}
