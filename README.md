# 學校公開網站檔案個資查驗系統

Flask + React/Vite MVP for checking files before publication to a school public website.

## Features

- Upload limits: 25 MB per file, 5 files per request by default.
- Supported types: PDF, DOCX, PPTX, XLSX, CSV, TXT, JPG/JPEG, PNG.
- Rejects oversized files with a clear split-file message.
- Deletes temporary source files after each scan.
- Stores only metadata, masked findings, review decisions, and audit rows in SQLite by default.
- Uses local Taiwan PII rules immediately; Azure AI services are optional via environment variables.
- Microsoft 365 / Office 365 sign-in through Microsoft Entra ID.
- Admin UI for Azure AI endpoints and API keys; keys are encrypted at rest and masked in API responses.

## Local Run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
npm --prefix frontend install
npm --prefix frontend run build
flask --app app:create_app run --debug
```

Open `http://127.0.0.1:5000`.

## Azure App Service

Use Python 3.12 on Azure App Service for Linux when possible.

Startup command:

```bash
gunicorn "app:create_app()" --bind=0.0.0.0:${PORT:-8000} --workers=1 --threads=8 --timeout=180
```

Set environment variables in App Service configuration:

```bash
FLASK_SECRET_KEY=...
DATABASE_PATH=/home/site/wwwroot/instance/app.db
MAX_FILE_MB=25
MAX_FILES_PER_UPLOAD=5
AUTH_REQUIRED=true
MS_TENANT_ID=<your-school-tenant-id>
MS_CLIENT_ID=<app-registration-client-id>
MS_CLIENT_SECRET=<app-registration-client-secret>
MS_REDIRECT_PATH=/auth/callback
AZURE_DOCUMENT_INTELLIGENCE_ENDPOINT=...
AZURE_DOCUMENT_INTELLIGENCE_KEY=...
AZURE_LANGUAGE_ENDPOINT=...
AZURE_LANGUAGE_KEY=...
AZURE_OPENAI_ENDPOINT=...
AZURE_OPENAI_KEY=...
AZURE_OPENAI_DEPLOYMENT=gpt-5-mini
AZURE_OPENAI_API_VERSION=2025-04-01-preview
```

For production, move from SQLite to Azure SQL and replace key auth with Managed Identity.

Azure AI settings can also be entered after login in the admin panel. If values are configured both in App Service environment variables and in the admin panel, the admin panel values are used for new scan jobs. API keys are encrypted with a key derived from `FLASK_SECRET_KEY`, so keep `FLASK_SECRET_KEY` stable after saving keys.

## Microsoft 365 Login Setup

Create an app registration in Microsoft Entra ID:

1. Add a Web redirect URI: `https://<your-app-name>.azurewebsites.net/auth/callback`.
2. Create a client secret and store it as `MS_CLIENT_SECRET` in App Service configuration.
3. Set `MS_TENANT_ID` to the school's tenant ID to restrict login to school accounts.
4. Keep the default delegated permission `User.Read`.

For local development without login:

```bash
AUTH_REQUIRED=false flask --app app:create_app run --debug
```
