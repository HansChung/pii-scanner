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

> 所有命中值在輸出時都會**自動遮罩**，僅保留前後幾碼，避免再次外洩。

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
- 上傳檔案掃描
- 輸入單一 URL 掃描
- 輸入起始 URL 進行整站爬取掃描

REST API 端點：

| 方法 | 路徑 | 表單欄位 |
| --- | --- | --- |
| `POST` | `/api/scan/text` | `text` |
| `POST` | `/api/scan/file` | `file` (multipart) |
| `POST` | `/api/scan/url`  | `url` |
| `POST` | `/api/scan/site` | `url`, `max_pages`, `max_depth` |
| `GET`  | `/healthz` | — |

回應格式範例：

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

## 設計與限制

- **偵測 vs 真值**：身分證、統編、信用卡使用官方檢核碼，誤判率低；姓名、地址、護照、健保卡、帳號則屬啟發式或需上下文關鍵字輔助，可能有漏報或誤報，建議搭配人工複核。
- **網站爬蟲**：預設遵守 `robots.txt`、限制同網域、可設定 delay，避免造成被掃描網站負擔。請只掃描你有權限掃描的網站。
- **資料保留**：本工具不會把命中值寫入永久檔，輸出報表中也都是遮罩後的值；若你要把原始值留存在 JSON，請自行加密保存。
- **效能**：採純 regex + 啟發式，可處理 MB 等級檔案；若要掃描大型資料倉儲，建議結合 Spark / DuckDB 等批次工具。
- **可選整合**：可在 `BaseDetector` 上擴充以接入 Microsoft Presidio、Google DLP 等服務做進一步的 NER 識別。

## 授權

MIT License
