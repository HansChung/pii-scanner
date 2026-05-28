# PII Scanner — 個資自動掃描系統

一個輕量、可擴充的個資 (PII, Personally Identifiable Information) 掃描工具，內建台灣常見個資格式的偵測規則。可用於：

- 對 **文字** / **檔案** / **整個專案目錄** 做合規檢查（如審核日誌、外部交付資料）
- 抓取 **單一網址** 或 **遞迴爬取整個網站**，檢查公開頁面是否意外曝光個資
- 提供 **CLI**、**REST API** 與 **Web UI** 三種使用方式
- 支援 **JSON / HTML / 終端機彩色** 三種報表輸出

> ⚠️ 法遵提醒：本工具僅能輔助找出疑似違反《個人資料保護法》的資料樣態。最終判斷與法律責任仍需由具備個資管理權限的人員或法務確認。

## 內建偵測器

| 偵測器 | 類別 | 嚴重度 | 驗證機制 |
| --- | --- | --- | --- |
| `taiwan_id` | 國民身分證字號 | critical | 加權檢核碼 |
| `taiwan_resident_cert` | 居留證 / 統一證號 (新舊版) | critical | 加權檢核碼 |
| `credit_card` | 信用卡卡號 | critical | Luhn 演算法 |
| `taiwan_mobile` | 台灣行動電話 | high | 09 開頭 8 位 / +886 |
| `taiwan_passport` | 護照號碼 | high | 9 位數 + 關鍵字 |
| `taiwan_nhi_card` | 健保卡號 | high | 12 位數 + 關鍵字 |
| `bank_account` | 銀行帳號 | high | 10-16 位數 + 關鍵字 |
| `email` | 電子郵件 | medium | 標準 Email 格式 |
| `taiwan_landline` | 市話 | medium | 區碼 + 6-8 位 |
| `taiwan_business_id` | 公司統一編號 | medium | 財政部檢核 |
| `date_of_birth` | 出生日期 | medium | 日期 + 關鍵字 |
| `taiwan_address` | 地址 | medium | 縣市 + 路 + 號 |
| `ipv4` / `ipv6` | IP 位址 | low | 標準格式 + 排除回送/未指定 |
| `taiwan_license_plate` | 車牌 | low | 新式格式 |
| `chinese_name` | 中文姓名 | low | 關鍵字 (姓名:) + 2-4 字 |
| `surname_name` | 中文姓名 | low | **百家姓詞表** + 名字長度 + 排除詞 |

> 所有命中值在輸出時都會**自動遮罩**，僅保留前後幾碼，避免再次外洩。

### 百家姓姓名偵測 (`surname_name`)

不需 LLM，以 **姓氏詞表 + 規則** 在全文掃描：

- 收錄百家姓單姓、常見複姓（歐陽、司馬、諸葛…）
- 複姓優先比對（長度優先）
- 排除詞過濾（陳情、王國、台北…）
- 名字不可含虛詞/動詞（將、是、在…）
- 過濾職稱/機構後綴（先生、公司、銀行…）

三種模式：

```python
from pii_scanner.detectors import SurnameNameDetector, SurnameMatchMode, detect_in_text

# balanced（預設，已加入 ALL_DETECTORS）
findings = detect_in_text("承辦人王小明已完成。")

# strict：僅在標點/空白邊界比對，誤判更少
det = SurnameNameDetector(mode=SurnameMatchMode.STRICT)

# aggressive：過濾最少，召回率高但誤判也多
det = SurnameNameDetector(mode=SurnameMatchMode.AGGRESSIVE)
```

## 安裝

```bash
git clone <repo>
cd <repo>
pip install -r requirements.txt
```

需要 Python 3.10+。

## CLI 使用

```bash
# 掃描單一字串
python -m pii_scanner.cli scan-text "客戶 A123456789 手機 0912-345-678"

# 掃描檔案
python -m pii_scanner.cli scan-file examples/sample_data.txt

# 遞迴掃描整個目錄，並輸出 HTML 報表
python -m pii_scanner.cli scan-dir ./logs --format html -o report.html

# 掃描單一 URL
python -m pii_scanner.cli scan-url https://example.com/contact

# 遞迴爬取整個網站 (預設遵守 robots.txt、同網域、深度 2、最多 30 頁)
python -m pii_scanner.cli scan-site https://example.com --max-pages 50 --max-depth 2

# 輸出 JSON 供其他工具消費
python -m pii_scanner.cli scan-dir ./src --format json -o findings.json
```

CLI 在有命中時 exit code = 1，無命中時 = 0，方便整合進 CI/CD：

```yaml
# .github/workflows/pii.yml 範例片段
- run: pip install -r requirements.txt
- run: python -m pii_scanner.cli scan-dir ./ --format json -o pii-report.json
```

## Web UI / REST API

```bash
uvicorn pii_scanner.web.app:app --host 0.0.0.0 --port 8000
```

開啟瀏覽器 <http://localhost:8000> 即可看到網頁介面，支援：

- 貼上文字即時掃描
- 上傳檔案掃描（文字、Excel、開放文件格式，見下方）
- 輸入單一 URL 掃描（可直接貼上 PDF / Word / Excel 下載連結）
- 輸入起始 URL 進行整站爬取掃描（會跟進頁面上的文件下載連結）

### 掃描報告：依頁面 / 檔案摘要

不論上傳檔案、單一 URL 或整站爬取，報告都會提供 **依頁面 / 檔案摘要**：

| 類型 | 說明 | 位置明細範例 |
| --- | --- | --- |
| 網頁 | HTML 頁面 URL | （全文） |
| 下載文件 | 從網站抓取的 PDF / Word / Excel | 第 1 頁、工作表名 |
| 本機檔案 | 上傳或 CLI 掃描的檔案路徑 | 第 1 頁、工作表名 |

無法抓取或解析的 URL / 檔案會列在 **scan_issues**（Web UI 顯示為「無法掃描的 URL / 檔案」）。

### 網址與整站掃描中的文件

單一 URL 若直接指向 `.pdf`、`.docx`、`.xlsx` 等支援格式，或 Content-Type 為對應 MIME 類型，會與檔案上傳相同方式解析。整站爬取時，HTML 頁面上的文件下載連結也會被抓取並掃描（計入 `max_pages`；單檔上限 5 MB）。下載文件的命中 `source` 為 `https://…/file.pdf#page=1` 格式，便於與一般網頁區分。

### 上傳檔案格式

| 類型 | 副檔名 | 說明 |
| --- | --- | --- |
| 文字 | `.txt` `.csv` `.json` `.html` `.md` `.log` 等 | 依 UTF-8 / Big5 解碼 |
| Excel | `.xlsx` `.xlsm` | **逐工作表**掃描；結果 `source` 顯示 `檔名#工作表名` |
| OpenDocument 試算表 | `.ods` | 逐工作表（開放文件格式） |
| OpenDocument 文字 | `.odt` | 段落與表格 |
| Word | `.docx` | 段落與表格 |
| PDF | `.pdf` | **逐頁**擷取文字；結果 `source` 顯示 `檔名#page=1` |

Excel / ODS 若有多個分頁，每一頁各自擷取儲存格文字並掃描，命中結果會標示來源工作表。  
上傳 Excel 時即使副檔名錯誤（如 `.xls` 或無副檔名），系統會依檔案內容自動辨識格式。
PDF 逐頁掃描；若 PDF 為掃描影像（無文字層），目前無法分析，需 OCR 後再上傳文字檔。  
環境變數 `PII_MAX_DOCUMENT_SHEETS`（預設 30，亦適用 PDF 頁數）、`PII_MAX_DOCUMENT_ROWS`（預設 5000）可限制單檔規模。

REST API 端點：

| 方法 | 路徑 | 表單欄位 |
| --- | --- | --- |
| `POST` | `/api/scan/text` | `text` |
| `POST` | `/api/scan/file` | `file` (multipart) |
| `POST` | `/api/scan/url`  | `url` |
| `POST` | `/api/scan/site` | `url`, `max_pages`, `max_depth` |
| `GET`  | `/healthz` | — |

## 管理介面與白名單

### 百家姓偵測（預設關閉）

`surname_name`（百家姓全文掃描）在網站內容容易誤判（如「淡江」「國際」「獎助學金」），**預設已關閉**。  
僅保留 `chinese_name`（需有「姓名：」等關鍵字）。

若需啟用百家姓：Azure 設定 `PII_ENABLE_SURNAME_NAME=true`（不建議用於整站爬蟲）。

### 白名單管理 `/admin`

1. Azure **應用程式設定** 新增：
   ```
   PII_ADMIN_PASSWORD = 你的管理密碼
   PII_WHITELIST_PATH = /home/site/whitelist/config.json
   ```
   （`/home/site/` 在 App Service 重部署後仍保留）

2. 開啟 `https://<你的-webapp>.azurewebsites.net/admin`  
   帳號：`admin` / 密碼：上述設定值

3. 可設定：
   - **全域停用偵測器**（如 address、email）
   - **全域忽略詞**（如公開 Email、校名）
   - **依網域規則**（如 `tku.edu.tw` 停用地址偵測）

範例：淡江官網掃描時，新增網域規則 `tku.edu.tw`，停用 `taiwan_address`，忽略詞填 `president@mail.tku.edu.tw`。

---

本專案已針對 **B1 Linux（1 vCPU / 1.75GB RAM）** 優化，無需 Presidio。

### 1. 建立 App Service（Azure CLI 範例）

```bash
RESOURCE_GROUP="rg-pii-scanner"
LOCATION="eastasia"
APP_PLAN="plan-pii-b1"
WEBAPP="pii-scanner-yourname"   # 全小寫、全域唯一

az group create -n $RESOURCE_GROUP -l $LOCATION
az appservice plan create -g $RESOURCE_GROUP -n $APP_PLAN --sku B1 --is-linux
az webapp create -g $RESOURCE_GROUP -p $APP_PLAN -n $WEBAPP \
  --runtime "PYTHON:3.12"
```

### 2. 設定啟動命令與建議選項

在 Azure Portal → **設定 → 一般設定**，或 CLI：

```bash
az webapp config set -g $RESOURCE_GROUP -n $WEBAPP \
  --startup-file "bash startup.sh"

# 建議：Always On（B1 支援，避免冷啟動）
az webapp config set -g $RESOURCE_GROUP -n $WEBAPP --always-on true

# 健康檢查（Portal → 健康檢查 → 路徑 /healthz）
```

**應用程式設定（Application settings）— B1 建議值：**

| 名稱 | 值 | 說明 |
| --- | --- | --- |
| `SCM_DO_BUILD_DURING_DEPLOYMENT` | `true` | 部署時 pip install |
| `WEB_CONCURRENCY` | `1` | B1 固定 1 worker（預設） |
| `PII_MAX_UPLOAD_MB` | `5` | 上傳上限（預設 5MB） |
| `PII_MAX_SITE_PAGES` | `10` | 整站爬蟲最多頁數 |
| `PII_HTTP_TIMEOUT` | `15` | 單次 HTTP 逾時（秒） |
| `PII_ADMIN_PASSWORD` | （自行設定） | 啟用 `/admin` 管理白名單 |
| `PII_WHITELIST_PATH` | `/home/site/whitelist/config.json` | 白名單儲存路徑（Azure 建議） |

### Azure AI 增強分析（選用，勾選才計費）

可在掃描頁勾選 **「Azure AI 增強分析」**，額外呼叫 [Azure AI Language PII](https://learn.microsoft.com/azure/ai-services/language-service/personally-identifiable-information) 加強姓名等語意偵測。**預設關閉**，只有勾選時才會產生 API 費用。

| 名稱 | 值 | 說明 |
| --- | --- | --- |
| `AZURE_LANGUAGE_ENDPOINT` | `https://<資源>.cognitiveservices.azure.com/` | Language 服務端點 |
| `AZURE_LANGUAGE_KEY` | （金鑰） | 與端點配對的 Key |
| `PII_AI_MAX_CHARS` | `5000` | 單次 AI 分析字元上限（控管費用） |
| `PII_AI_ALLOW_SITE_SCAN` | `false` | 整站爬取是否允許 AI（預設否，避免多頁費用） |

未設定端點與金鑰時，勾選框不會顯示；設定後重新整理首頁即可使用。

升級至 S1 後可將 `WEB_CONCURRENCY` 改為 `2`、`PII_MAX_SITE_PAGES` 改為 `20`。

### 3. 部署方式

**方式 A — GitHub Actions（推薦）**

1. Azure Portal → Web App → **部署中心** → 下載 **Publish Profile**
2. GitHub Repo → Settings → Secrets：
   - `AZURE_WEBAPP_NAME` = 你的 Web App 名稱
   - `AZURE_WEBAPP_PUBLISH_PROFILE` = Publish Profile 全文
3. push 到 `main` 即自動部署（`.github/workflows/azure-webapp.yml`）

**方式 B — 本機 zip 部署**

```bash
az webapp deploy -g $RESOURCE_GROUP -n $WEBAPP \
  --src-path . --type zip
```

### 4. 驗證

```bash
curl https://$WEBAPP.azurewebsites.net/healthz
# 預期回應: ok
```

開啟 `https://<你的-webapp>.azurewebsites.net/` 即可使用 Web UI。

### B1 限制提醒

| 項目 | B1 限制 | 本專案因應 |
| --- | --- | --- |
| RAM 1.75GB | 不宜多 worker | `startup.sh` 預設 1 worker |
| 請求逾時 ~230s | 整站爬蟲不宜過久 | 預設最多 10 頁 |
| 上傳大小 | Platform 上限 ~30MB | API 預設限 5MB |
| 冷啟動 | 閒置後首次較慢 | 建議開 Always On |

### 5. 安全建議（正式環境）

- 啟用 **Authentication**（Microsoft Entra ID），避免公開掃描介面
- 敏感設定放 **Key Vault** 參考，不要 commit `.env`
- 只掃描有授權的網站；整站爬蟲預設遵守 `robots.txt`

---

### API 回應格式範例

```json
{
  "summary": {
    "total": 4,
    "by_severity": {"critical": 2, "high": 1, "medium": 1},
    "by_category": {"national_id": 1, "financial": 1, "phone": 1, "email": 1},
    "by_detector": {"taiwan_id": 1, "credit_card": 1, "taiwan_mobile": 1, "email": 1},
    "sources": ["api:text"],
    "generated_at": "2026-05-26T08:40:00+00:00"
  },
  "findings": [
    {
      "detector": "taiwan_id",
      "category": "national_id",
      "severity": "critical",
      "value": "A123456789",
      "masked": "A1******89",
      "start": 12, "end": 22,
      "context": "…客戶 A123456789 手機…",
      "source": "api:text",
      "notes": "台灣身分證字號 (通過檢核碼)"
    }
  ]
}
```

## 程式 API

```python
from pii_scanner import scan_text, scan_file, scan_directory, scan_url, scan_site
from pii_scanner.report import render_json, render_html, render_terminal

findings = scan_text("身分證 A123456789 信用卡 4111 1111 1111 1111")
print(render_terminal(findings))

findings = scan_directory("./data")
open("report.html", "w").write(render_html(findings))

findings = scan_site("https://example.com", max_pages=20)
```

## 擴充偵測器

新增一個偵測器只需要：

1. 繼承 `pii_scanner.detectors.base.BaseDetector`
2. 實作 `detect(text) -> Iterable[Finding]`
3. 把實例加進 `pii_scanner.detectors.ALL_DETECTORS`

```python
from pii_scanner.detectors.base import BaseDetector, Severity
import re

class MyAPIKeyDetector(BaseDetector):
    name = "internal_api_key"
    category = "secret"
    severity = Severity.CRITICAL
    pattern = re.compile(r"INT-[A-Z0-9]{16}")

    def detect(self, text):
        for m in self.pattern.finditer(text):
            yield self.make_finding(text, m.group(0), m.start(), m.end())
```

## 測試

```bash
pip install pytest
pytest
```

## 與第三方工具比較（要錢嗎？）

| 工具 | 軟體授權費 | 實際可能產生的費用 | 說明 |
| --- | --- | --- | --- |
| **本專案 (pii-scanner)** | **免費** (MIT) | 只有你自己機器/VM 的運算成本 | 純 Python，無雲端綁定 |
| **Microsoft Presidio** | **免費** (Apache 2.0 開源) | 若部署在 Azure VM/K8s/Container Apps → **基礎設施費**；Presidio 本身不收授權費 | `pip install presidio-analyzer` 即可本地跑；中文 NER 需額外模型 |
| **Google Cloud DLP** | 無開源版 | **按量計費**（依檢查資料量 GB、API 呼叫次數） | 新帳號可能有 **$300 試用額度**，但正式使用需綁 GCP 信用卡；有免費配額但有限 |
| **AWS Macie** | 無開源版 | **按量計費**（S3 掃描、資料量） | 專為 AWS S3 設計 |
| **Azure AI Language PII** | 無開源版 | **按 API 呼叫次數計費** | 微軟託管服務，非 Presidio 開源版 |

**實務建議：**

1. **預算有限 / 資料不能出公司** → 用本專案或 Presidio **本地部署**（零授權費）
2. **已在 GCP 且資料已在 Cloud Storage** → 評估 Cloud DLP（方便但會持續產生帳單）
3. **需要最高準確度 + 多語言 NER** → Presidio + spaCy 模型，或 Cloud DLP 試用後比較誤判率

> Google Cloud DLP 與 Azure PII 都是「把資料送到雲端 API 分析」，有**資料外送與合規**議題；Presidio / 本專案可在內網離線執行。

## 設計與限制

- **偵測 vs 真值**：身分證、統編、信用卡使用官方檢核碼，誤判率低；姓名、地址、護照、健保卡、帳號則屬啟發式或需上下文關鍵字輔助，可能有漏報或誤報，建議搭配人工複核。
- **網站爬蟲**：預設遵守 `robots.txt`、限制同網域、可設定 delay，避免造成被掃描網站負擔。請只掃描你有權限掃描的網站。
- **資料保留**：本工具不會把命中值寫入永久檔，輸出報表中也都是遮罩後的值；若你要把原始值留存在 JSON，請自行加密保存。
- **效能**：採純 regex + 啟發式，可處理 MB 等級檔案；若要掃描大型資料倉儲，建議結合 Spark / DuckDB 等批次工具。
- **可選整合**：可在 `BaseDetector` 上擴充以接入 Microsoft Presidio、Google DLP 等服務做進一步的 NER 識別。

## 授權

MIT License
icense
