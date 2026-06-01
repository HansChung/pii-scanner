from __future__ import annotations


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

