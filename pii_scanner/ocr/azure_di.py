"""Azure AI Document Intelligence OCR 包裝。

當 PDF 無文字層時使用；以 `prebuilt-read` 模型直接送 PDF 二進位，
回傳 ``{page_number: text}``。需設定環境變數：

- ``AZURE_DOCUMENT_INTELLIGENCE_ENDPOINT``
- ``AZURE_DOCUMENT_INTELLIGENCE_KEY``
"""
from __future__ import annotations

import logging
from typing import Dict

from ..settings import AZURE_DI_ENDPOINT, AZURE_DI_KEY, OCR_MAX_PAGES

log = logging.getLogger(__name__)


class OcrError(Exception):
    """OCR 處理錯誤。"""


def is_configured() -> bool:
    return bool(AZURE_DI_ENDPOINT and AZURE_DI_KEY)


def ocr_pdf_pages(data: bytes, *, max_pages: int = OCR_MAX_PAGES) -> Dict[int, str]:
    """以 Azure DI `prebuilt-read` 對 PDF 做 OCR；回傳 {頁碼: 文字}。

    Raises:
        OcrError: 未設定金鑰、SDK 缺失或 API 失敗。
    """
    if not is_configured():
        raise OcrError(
            "Azure Document Intelligence 未設定。請在 App Service 設定 "
            "AZURE_DOCUMENT_INTELLIGENCE_ENDPOINT 與 AZURE_DOCUMENT_INTELLIGENCE_KEY。"
        )

    try:
        from azure.ai.documentintelligence import DocumentIntelligenceClient
        from azure.ai.documentintelligence.models import AnalyzeDocumentRequest
        from azure.core.credentials import AzureKeyCredential
        from azure.core.exceptions import HttpResponseError
    except ImportError as exc:  # pragma: no cover - 缺套件僅環境問題
        raise OcrError(
            "缺少 azure-ai-documentintelligence 套件；請執行 `pip install -r requirements.txt`。"
        ) from exc

    client = DocumentIntelligenceClient(
        endpoint=AZURE_DI_ENDPOINT,
        credential=AzureKeyCredential(AZURE_DI_KEY),
    )

    try:
        poller = client.begin_analyze_document(
            "prebuilt-read",
            AnalyzeDocumentRequest(bytes_source=data),
        )
        result = poller.result()
    except HttpResponseError as exc:
        raise OcrError(f"Azure Document Intelligence 失敗：{exc.message}") from exc
    except Exception as exc:  # noqa: BLE001
        raise OcrError(f"OCR 呼叫失敗：{exc}") from exc

    pages: Dict[int, str] = {}
    page_list = getattr(result, "pages", None) or []
    for i, page in enumerate(page_list, 1):
        if max_pages and i > max_pages:
            log.warning("OCR 超過 %s 頁，已截斷", max_pages)
            break
        page_no = getattr(page, "page_number", None) or i
        lines = getattr(page, "lines", None) or []
        text = "\n".join(getattr(l, "content", "") for l in lines if getattr(l, "content", ""))
        if text.strip():
            pages[page_no] = text
    return pages
