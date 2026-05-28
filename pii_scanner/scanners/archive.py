"""ZIP 壓縮包解析：取出成員後遞迴呼叫 scan_bytes。

設計目標：
- 安全：限制成員數、單檔大小、總解壓位元數，避免 zip-bomb。
- 一致：成員 source 沿用 ``archive.zip!內部路徑``，再加上原本的 ``#工作表/頁碼``。
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from io import BytesIO
from typing import List
from zipfile import BadZipFile, ZipFile

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class ArchiveMember:
    name: str
    data: bytes
    size: int


class ArchiveReadError(Exception):
    """壓縮包無法解析。"""


# 預設安全上限（可被 settings 覆寫）
DEFAULT_MAX_FILES = 80
DEFAULT_MAX_TOTAL_BYTES = 20 * 1024 * 1024   # 20 MB 總解壓
DEFAULT_MAX_MEMBER_BYTES = 5 * 1024 * 1024   # 5 MB 單檔


def is_zip_archive(data: bytes) -> bool:
    """是否為 ZIP 容器（且非 Office/OpenDocument 結構）。"""
    if len(data) < 4 or data[:4] != b"PK\x03\x04":
        return False
    try:
        with ZipFile(BytesIO(data)) as zf:
            names = set(zf.namelist())
    except (BadZipFile, OSError):
        return False
    # Office / OpenDocument 雖也是 ZIP，但已由 sniff_document_suffix 處理
    if any(n.startswith("xl/") or n.startswith("word/") or n.startswith("ppt/") for n in names):
        return False
    if "mimetype" in names:
        try:
            mt = zf.read("mimetype").decode("utf-8", errors="ignore")  # type: ignore[name-defined]
        except Exception:
            mt = ""
        if mt.startswith("application/vnd.oasis.opendocument."):
            return False
    return True


def extract_zip_members(
    data: bytes,
    *,
    max_files: int = DEFAULT_MAX_FILES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_member_bytes: int = DEFAULT_MAX_MEMBER_BYTES,
) -> List[ArchiveMember]:
    """解出 ZIP 成員。會略過目錄項目、過大檔案，並執行安全限制。"""
    try:
        zf = ZipFile(BytesIO(data))
    except (BadZipFile, OSError) as exc:
        raise ArchiveReadError(f"無法開啟壓縮包：{exc}") from exc

    members: List[ArchiveMember] = []
    total_bytes = 0
    try:
        for info in zf.infolist():
            if len(members) >= max_files:
                log.warning("壓縮包成員超過 %d，後續略過", max_files)
                break
            if info.is_dir():
                continue
            if info.file_size > max_member_bytes:
                log.info("壓縮包成員 %s 超過 %d bytes，略過", info.filename, max_member_bytes)
                continue
            if total_bytes + info.file_size > max_total_bytes:
                log.warning(
                    "壓縮包總解壓量超過 %d bytes，停止後續成員", max_total_bytes
                )
                break
            try:
                with zf.open(info, "r") as fp:
                    payload = fp.read(max_member_bytes + 1)
            except Exception as exc:  # noqa: BLE001
                log.warning("讀取壓縮包成員 %s 失敗：%s", info.filename, exc)
                continue
            if len(payload) > max_member_bytes:
                log.info("壓縮包成員 %s 解壓超過 %d，截斷", info.filename, max_member_bytes)
                payload = payload[:max_member_bytes]
            total_bytes += len(payload)
            members.append(ArchiveMember(name=info.filename, data=payload, size=len(payload)))
    finally:
        zf.close()
    return members
