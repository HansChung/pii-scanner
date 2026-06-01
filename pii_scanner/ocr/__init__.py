"""OCR 模組（影像 PDF 文字辨識）。"""
from .azure_di import OcrError, is_configured, ocr_pdf_pages

__all__ = ["OcrError", "is_configured", "ocr_pdf_pages"]
