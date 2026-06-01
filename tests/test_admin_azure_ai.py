from __future__ import annotations

from unittest.mock import MagicMock, patch


def test_admin_can_save_azure_ai_key_without_plaintext_echo(client):
    response = client.put(
        "/api/admin/azure-ai",
        json={
            "azureDocumentIntelligenceEndpoint": "https://doc.example.com",
            "azureDocumentIntelligenceKey": "doc-secret-123456",
            "azureDocumentIntelligenceApiVersion": "2024-11-30",
        },
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["azureDocumentIntelligenceEndpoint"] == "https://doc.example.com"
    assert payload["azureDocumentIntelligenceKey"]["configured"] is True
    assert "doc-secret-123456" not in str(payload)


def test_blank_secret_update_keeps_existing_secret(client):
    client.put("/api/admin/azure-ai", json={"azureOpenAiKey": "openai-secret-abcdef"})
    response = client.put(
        "/api/admin/azure-ai",
        json={"azureOpenAiEndpoint": "https://openai.example.com", "azureOpenAiKey": ""},
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["azureOpenAiEndpoint"] == "https://openai.example.com"
    assert payload["azureOpenAiKey"]["configured"] is True


def test_document_intelligence_connection_test_requires_saved_settings(client):
    response = client.post("/api/admin/azure-ai/test", json={"service": "documentIntelligence"})
    assert response.status_code == 400
    assert "Document Intelligence" in response.get_json()["message"]


def test_document_intelligence_connection_test_uses_prebuilt_read(client):
    client.put(
        "/api/admin/azure-ai",
        json={
            "azureDocumentIntelligenceEndpoint": "https://doc.example.com",
            "azureDocumentIntelligenceKey": "doc-secret-123456",
            "azureDocumentIntelligenceApiVersion": "2024-11-30",
        },
    )
    analyze_response = MagicMock()
    analyze_response.headers = {"operation-location": "https://doc.example.com/operations/1"}
    analyze_response.raise_for_status.return_value = None
    poll_response = MagicMock()
    poll_response.json.return_value = {"status": "succeeded", "analyzeResult": {}}
    poll_response.raise_for_status.return_value = None

    with (
        patch("app.azure_services.requests.post", return_value=analyze_response) as post,
        patch("app.azure_services.requests.get", return_value=poll_response),
    ):
        response = client.post(
            "/api/admin/azure-ai/test",
            json={"service": "documentIntelligence"},
        )

    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"
    assert "prebuilt-read:analyze" in post.call_args.args[0]
