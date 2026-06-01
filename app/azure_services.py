from __future__ import annotations

import json
import time
from io import BytesIO
from pathlib import Path

import requests
from PIL import Image, ImageDraw

from .models import ExtractedText, Finding
from .pii_rules import mask_value
from .secret_settings import effective_azure_ai_config


def document_intelligence_enabled() -> bool:
    config = effective_azure_ai_config()
    return bool(config["azureDocumentIntelligenceEndpoint"] and config["azureDocumentIntelligenceKey"])


def language_pii_enabled() -> bool:
    config = effective_azure_ai_config()
    return bool(config["azureLanguageEndpoint"] and config["azureLanguageKey"])


def azure_openai_enabled() -> bool:
    config = effective_azure_ai_config()
    return bool(config["azureOpenAiEndpoint"] and config["azureOpenAiKey"])


def test_azure_ai_service(service: str) -> str:
    if service == "documentIntelligence":
        return _test_document_intelligence()
    if service == "language":
        if not language_pii_enabled():
            raise ValueError("請先保存 Azure AI Language Endpoint 與 API key。")
        detect_with_azure_language("連線測試：姓名王小明", "Azure AI 連線測試")
        return "Azure AI Language PII 連線成功。"
    if service == "openAi":
        _test_azure_openai()
        return "Azure OpenAI 連線成功。"
    raise ValueError("不支援的 Azure AI 服務。")


def _test_document_intelligence() -> str:
    config = effective_azure_ai_config()
    endpoint = config["azureDocumentIntelligenceEndpoint"].rstrip("/")
    key = config["azureDocumentIntelligenceKey"]
    api_version = config["azureDocumentIntelligenceApiVersion"]
    if not endpoint or not key:
        raise ValueError("請先保存 Document Intelligence Endpoint 與 API key。")
    image = Image.new("RGB", (360, 100), "white")
    ImageDraw.Draw(image).text((18, 36), "OCR CONNECTION TEST", fill="black")
    content = BytesIO()
    image.save(content, format="PNG")
    response = requests.post(
        (
            f"{endpoint}/documentintelligence/documentModels/prebuilt-read:analyze"
            f"?api-version={api_version}"
        ),
        headers={"Ocp-Apim-Subscription-Key": key, "Content-Type": "image/png"},
        data=content.getvalue(),
        timeout=30,
    )
    response.raise_for_status()
    operation_url = response.headers["operation-location"]
    for _ in range(20):
        poll = requests.get(
            operation_url,
            headers={"Ocp-Apim-Subscription-Key": key},
            timeout=15,
        )
        poll.raise_for_status()
        payload = poll.json()
        if payload.get("status") == "succeeded":
            return "Document Intelligence OCR 連線成功，prebuilt-read 已完成測試圖片辨識。"
        if payload.get("status") == "failed":
            raise RuntimeError("Document Intelligence OCR 測試失敗。")
        time.sleep(1)
    raise TimeoutError("Document Intelligence OCR 連線測試逾時。")


def _test_azure_openai() -> None:
    config = effective_azure_ai_config()
    endpoint = config["azureOpenAiEndpoint"].rstrip("/")
    deployment = config["azureOpenAiDeployment"]
    key = config["azureOpenAiKey"]
    api_version = config["azureOpenAiApiVersion"]
    if not endpoint or not key or not deployment:
        raise ValueError("請先保存 Azure OpenAI Endpoint、API key 與 Deployment。")
    response = requests.post(
        f"{endpoint}/openai/deployments/{deployment}/chat/completions?api-version={api_version}",
        headers={"api-key": key, "Content-Type": "application/json"},
        json={"messages": [{"role": "user", "content": "Reply with OK."}]},
        timeout=45,
    )
    response.raise_for_status()


def extract_with_document_intelligence(path: Path) -> list[ExtractedText]:
    config = effective_azure_ai_config()
    endpoint = config["azureDocumentIntelligenceEndpoint"].rstrip("/")
    key = config["azureDocumentIntelligenceKey"]
    api_version = config["azureDocumentIntelligenceApiVersion"]
    url = (
        f"{endpoint}/documentintelligence/documentModels/prebuilt-read:analyze"
        f"?api-version={api_version}"
    )
    with path.open("rb") as handle:
        response = requests.post(
            url,
            headers={"Ocp-Apim-Subscription-Key": key, "Content-Type": "application/octet-stream"},
            data=handle,
            timeout=30,
        )
    response.raise_for_status()
    operation_url = response.headers["operation-location"]
    for _ in range(60):
        poll = requests.get(
            operation_url,
            headers={"Ocp-Apim-Subscription-Key": key},
            timeout=15,
        )
        poll.raise_for_status()
        payload = poll.json()
        status = payload.get("status")
        if status == "succeeded":
            result = payload.get("analyzeResult", {})
            chunks = []
            for page in result.get("pages", []):
                page_no = page.get("pageNumber", "?")
                lines = [line.get("content", "") for line in page.get("lines", [])]
                text = "\n".join(item for item in lines if item)
                if text.strip():
                    chunks.append(ExtractedText(text=text, location=f"第 {page_no} 頁 OCR"))
            if not chunks and result.get("content"):
                chunks.append(ExtractedText(text=result["content"], location="OCR 全文"))
            return chunks
        if status == "failed":
            raise RuntimeError(json.dumps(payload.get("error", {}), ensure_ascii=False))
        time.sleep(2)
    raise TimeoutError("Azure Document Intelligence OCR 逾時")


def detect_with_azure_language(text: str, location: str) -> list[Finding]:
    config = effective_azure_ai_config()
    endpoint = config["azureLanguageEndpoint"].rstrip("/")
    key = config["azureLanguageKey"]
    api_version = config["azureLanguageApiVersion"]
    url = f"{endpoint}/language/:analyze-text?api-version={api_version}"
    payload = {
        "kind": "PiiEntityRecognition",
        "parameters": {"modelVersion": "latest"},
        "analysisInput": {"documents": [{"id": "1", "language": "zh-hant", "text": text[:5000]}]},
    }
    response = requests.post(
        url,
        headers={"Ocp-Apim-Subscription-Key": key, "Content-Type": "application/json"},
        json=payload,
        timeout=30,
    )
    response.raise_for_status()
    entities = (
        response.json()
        .get("results", {})
        .get("documents", [{}])[0]
        .get("entities", [])
    )
    findings = []
    for entity in entities:
        value = entity.get("text", "")
        category = entity.get("category", "PII")
        confidence = float(entity.get("confidenceScore", 0.0))
        findings.append(
            Finding(
                detector="azure-language-pii",
                category=category,
                risk_level=_risk_for_category(category),
                confidence=confidence,
                masked_text=mask_value(value),
                location=location,
                recommendation="Azure PII 偵測到疑似個資，公開前請確認是否必要並遮罩。",
            )
        )
    return findings


def detect_school_context_with_openai(text: str, location: str) -> list[Finding]:
    config = effective_azure_ai_config()
    endpoint = config["azureOpenAiEndpoint"].rstrip("/")
    deployment = config["azureOpenAiDeployment"]
    key = config["azureOpenAiKey"]
    api_version = config["azureOpenAiApiVersion"]
    url = f"{endpoint}/openai/deployments/{deployment}/chat/completions?api-version={api_version}"
    prompt = (
        "你是學校公開網站個資審查助手。只回 JSON array。"
        "找出校務情境中不應公開的個資風險，例如學生名冊、成績、獎懲、特教、醫療、家庭、低收入戶。"
        "每筆格式包含 category, risk_level, masked_text, recommendation。"
        "masked_text 不得包含完整個資。文字如下：\n"
        f"{text[:6000]}"
    )
    response = requests.post(
        url,
        headers={"api-key": key, "Content-Type": "application/json"},
        json={
            "messages": [
                {"role": "system", "content": "Return only valid JSON. No markdown."},
                {"role": "user", "content": prompt},
            ],
            "response_format": {"type": "json_object"},
        },
        timeout=45,
    )
    response.raise_for_status()
    content = response.json()["choices"][0]["message"]["content"]
    data = json.loads(content)
    items = data.get("findings", data if isinstance(data, list) else [])
    findings = []
    for item in items:
        masked = str(item.get("masked_text", "")).strip()
        if not masked:
            continue
        findings.append(
            Finding(
                detector="azure-openai-gpt-5-mini",
                category=str(item.get("category", "SchoolContextRisk")),
                risk_level=str(item.get("risk_level", "Medium")),
                confidence=0.75,
                masked_text=masked,
                location=location,
                recommendation=str(item.get("recommendation", "請由審核者確認是否適合公開。")),
            )
        )
    return findings


def _risk_for_category(category: str) -> str:
    high = {
        "PersonType",
        "PhoneNumber",
        "Address",
        "DateOfBirth",
        "DriversLicenseNumber",
        "PassportNumber",
        "NationalID",
        "CreditCardNumber",
        "BankAccountNumber",
    }
    return "High" if category in high else "Medium"
