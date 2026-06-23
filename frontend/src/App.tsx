import { useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { AlertTriangle, CheckCircle2, CircleStop, FileSearch, Gauge, Globe2, KeyRound, Link, ListFilter, Loader2, LogOut, PlugZap, Plus, Settings, ShieldCheck, Trash2, UploadCloud, UserRound } from 'lucide-react';
import { createRoot } from 'react-dom/client';
import './styles.css';

type ScanMeta = {
  mode: string;
  stats: {
    pages_scanned?: number;
    html_scanned?: number;
    documents_scanned?: number;
    archives_scanned?: number;
    text_scanned?: number;
    sitemap_seeded?: number;
    bytes_total?: number;
    start_url?: string;
    current_url?: string;
    queue_size?: number;
    max_pages?: number;
    scanned_urls?: string[];
    document_urls?: WebsiteAsset[];
    archive_urls?: WebsiteAsset[];
    text_urls?: WebsiteAsset[];
    skipped_urls?: Array<{ url: string; reason: string }>;
  };
  issues: Array<{ path: string; reason: string }>;
};

type WebsiteAsset = {
  url: string;
  status: string;
  bytes?: number;
  type?: string;
};

type Job = {
  id: string;
  status: string;
  progress: number;
  message: string | null;
  risk_level: string;
  created_at: string;
  updated_at: string;
  scanMeta?: ScanMeta | null;
  files: Array<{
    id: string;
    original_name: string;
    extension: string;
    size: number;
    status: string;
    error: string | null;
  }>;
};

type Finding = {
  id: string;
  original_name: string;
  detector: string;
  category: string;
  risk_level: string;
  confidence: number;
  masked_text: string;
  location: string;
  recommendation: string;
};

type SettingsShape = {
  maxFileMb: number;
  maxFilesPerUpload: number;
  allowedExtensions: string[];
  highRiskThreshold: number;
  dailyUserJobLimit: number;
  monthlyOcrPageLimit: number;
  monthlyLanguageRecordLimit: number;
  monthlyOpenAiTokenLimit: number;
  documentIntelligenceEnabled: boolean;
  languagePiiEnabled: boolean;
  openAiEnabled: boolean;
  openAiEscalationOnly: boolean;
};

type UsageEstimate = {
  ocrPages: number;
  languageRecords: number;
  openAiTokens: number;
};

type UsageSummary = {
  today: { userJobs: number };
  monthly: {
    ocrPages: UsageMetric;
    languageRecords: UsageMetric;
    openAiTokens: UsageMetric;
  };
  dailyUserJobLimit: number;
};

type UsageMetric = { used: number; limit: number; remaining: number };

type DomainRule = {
  domain: string;
  disabled_detectors: string[];
  ignore_words: string[];
};

type WhitelistConfig = {
  version: number;
  global_disabled_detectors: string[];
  ignore_words: string[];
  domain_rules: DomainRule[];
};

type WhitelistState = {
  config: WhitelistConfig;
  detectors: string[];
};

type AuthState = {
  authenticated: boolean;
  authRequired: boolean;
  authConfigured: boolean;
  isAdmin: boolean;
  user: null | {
    name: string;
    email: string;
    tenantId: string;
    objectId: string;
  };
};

type SecretStatus = {
  configured: boolean;
  masked: string;
};

type AzureAiSettings = {
  azureDocumentIntelligenceEndpoint: string;
  azureDocumentIntelligenceKey: SecretStatus;
  azureDocumentIntelligenceApiVersion: string;
  azureLanguageEndpoint: string;
  azureLanguageKey: SecretStatus;
  azureLanguageApiVersion: string;
  azureOpenAiEndpoint: string;
  azureOpenAiKey: SecretStatus;
  azureOpenAiDeployment: string;
  azureOpenAiApiVersion: string;
};

type AzureAiForm = {
  azureDocumentIntelligenceEndpoint: string;
  azureDocumentIntelligenceKey: string;
  azureDocumentIntelligenceApiVersion: string;
  azureLanguageEndpoint: string;
  azureLanguageKey: string;
  azureLanguageApiVersion: string;
  azureOpenAiEndpoint: string;
  azureOpenAiKey: string;
  azureOpenAiDeployment: string;
  azureOpenAiApiVersion: string;
};

type AzureAiService = 'documentIntelligence' | 'language' | 'openAi';
type RoleView = 'user' | 'admin';
type ScanSource = 'file' | 'website';
type WebsiteMode = 'url' | 'site';

type AzureAiTestResult = {
  tone: 'ok' | 'error';
  message: string;
};

const api = {
  async me(): Promise<AuthState> {
    const res = await fetch('/api/auth/me');
    return res.json();
  },
  async settings(): Promise<SettingsShape> {
    const res = await fetch('/api/admin/settings');
    return res.json();
  },
  async updateSettings(payload: Partial<SettingsShape>): Promise<SettingsShape> {
    const res = await fetch('/api/admin/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    return res.json();
  },
  async estimate(files: File[]): Promise<{ estimate: UsageEstimate; allowed: boolean; errors: string[] }> {
    const res = await fetch('/api/files/estimate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ files: files.map((file) => ({ name: file.name, size: file.size })) }),
    });
    return res.json();
  },
  async usage(): Promise<UsageSummary> {
    const res = await fetch('/api/admin/usage');
    return res.json();
  },
  async whitelist(): Promise<WhitelistState> {
    const res = await fetch('/api/admin/whitelist');
    return res.json();
  },
  async updateWhitelist(payload: WhitelistConfig): Promise<WhitelistState> {
    const res = await fetch('/api/admin/whitelist', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || '白名單保存失敗');
    return data;
  },
  async azureAiSettings(): Promise<AzureAiSettings> {
    const res = await fetch('/api/admin/azure-ai');
    return res.json();
  },
  async updateAzureAiSettings(payload: Partial<AzureAiForm>): Promise<AzureAiSettings> {
    const res = await fetch('/api/admin/azure-ai', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Azure AI 設定保存失敗');
    return data;
  },
  async testAzureAiService(service: AzureAiService): Promise<{ message: string }> {
    const res = await fetch('/api/admin/azure-ai/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ service }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || 'Azure AI 連線測試失敗');
    return data;
  },
  async upload(files: File[]) {
    const form = new FormData();
    files.forEach((file) => form.append('files', file));
    const res = await fetch('/api/files/check', { method: 'POST', body: form });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || '上傳失敗');
    return data as { jobId: string; status: string };
  },
  async scanWebsite(payload: { url: string; mode: WebsiteMode; maxPages: number; maxDepth: number; useSitemap: boolean; includePatterns: string[]; excludePatterns: string[] }) {
    const res = await fetch('/api/sites/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || '網站查驗失敗');
    return data as { jobId: string; status: string };
  },
  async job(jobId: string): Promise<Job> {
    const res = await fetch(`/api/jobs/${jobId}`);
    return res.json();
  },
  async findings(jobId: string): Promise<{ items: Finding[] }> {
    const res = await fetch(`/api/jobs/${jobId}/findings`);
    return res.json();
  },
  async cancel(jobId: string) {
    const res = await fetch(`/api/jobs/${jobId}/cancel`, { method: 'POST' });
    const data = await res.json();
    if (!res.ok) throw new Error(data.message || '取消任務失敗');
    return data as { jobId: string; status: string };
  },
  async review(jobId: string, decision: string, note: string) {
    const res = await fetch(`/api/jobs/${jobId}/review`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ decision, note, reviewer: 'demo-reviewer' }),
    });
    return res.json();
  },
};

function App() {
  const [auth, setAuth] = useState<AuthState | null>(null);
  const [settings, setSettings] = useState<SettingsShape | null>(null);
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [jobId, setJobId] = useState('');
  const [job, setJob] = useState<Job | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState('');
  const [azureSettings, setAzureSettings] = useState<AzureAiSettings | null>(null);
  const [azureForm, setAzureForm] = useState<AzureAiForm | null>(null);
  const [testingAzureService, setTestingAzureService] = useState<AzureAiService | null>(null);
  const [azureTestResults, setAzureTestResults] = useState<Partial<Record<AzureAiService, AzureAiTestResult>>>({});
  const [roleView, setRoleView] = useState<RoleView>('user');
  const [clock, setClock] = useState(() => Date.now());
  const [usageEstimate, setUsageEstimate] = useState<UsageEstimate | null>(null);
  const [estimateErrors, setEstimateErrors] = useState<string[]>([]);
  const [usage, setUsage] = useState<UsageSummary | null>(null);
  const [scanSource, setScanSource] = useState<ScanSource>('file');
  const [websiteMode, setWebsiteMode] = useState<WebsiteMode>('url');
  const [websiteUrl, setWebsiteUrl] = useState('');
  const [websiteMaxPages, setWebsiteMaxPages] = useState(10);
  const [websiteMaxDepth, setWebsiteMaxDepth] = useState(1);
  const [websiteUseSitemap, setWebsiteUseSitemap] = useState(false);
  const [websiteInclude, setWebsiteInclude] = useState('');
  const [websiteExclude, setWebsiteExclude] = useState('');
  const [whitelist, setWhitelist] = useState<WhitelistState | null>(null);

  useEffect(() => {
    api.me()
      .then((state) => {
        setAuth(state);
        if (state.authenticated || !state.authRequired) {
          return Promise.all([
            api.settings().then(setSettings),
            state.isAdmin ? Promise.all([api.azureAiSettings(), api.usage(), api.whitelist()]).then(([config, usageSummary, whitelistState]) => {
              setUsage(usageSummary);
              setWhitelist(whitelistState);
              setAzureSettings(config);
              setAzureForm({
                azureDocumentIntelligenceEndpoint: config.azureDocumentIntelligenceEndpoint,
                azureDocumentIntelligenceKey: '',
                azureDocumentIntelligenceApiVersion: config.azureDocumentIntelligenceApiVersion,
                azureLanguageEndpoint: config.azureLanguageEndpoint,
                azureLanguageKey: '',
                azureLanguageApiVersion: config.azureLanguageApiVersion,
                azureOpenAiEndpoint: config.azureOpenAiEndpoint,
                azureOpenAiKey: '',
                azureOpenAiDeployment: config.azureOpenAiDeployment,
                azureOpenAiApiVersion: config.azureOpenAiApiVersion,
              });
            }) : Promise.resolve(),
          ]);
        }
        return undefined;
      })
      .catch(() => setError('無法讀取登入狀態'));
  }, []);

  useEffect(() => {
    if (!selectedFiles.length) {
      setUsageEstimate(null);
      setEstimateErrors([]);
      return;
    }
    api.estimate(selectedFiles)
      .then((result) => {
        setUsageEstimate(result.estimate);
        setEstimateErrors(result.errors);
      })
      .catch(() => setEstimateErrors(['無法取得預估用量，請稍後再試。']));
  }, [selectedFiles]);

  useEffect(() => {
    if (!jobId) return;
    const timer = window.setInterval(async () => {
      const nextJob = await api.job(jobId);
      setJob(nextJob);
      if (isTerminalStatus(nextJob.status)) {
        const data = await api.findings(jobId);
        setFindings(data.items || []);
        window.clearInterval(timer);
      }
    }, 1200);
    return () => window.clearInterval(timer);
  }, [jobId]);

  useEffect(() => {
    if (!job || isTerminalStatus(job.status)) return;
    const timer = window.setInterval(() => setClock(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [job]);

  useEffect(() => {
    if (roleView === 'admin' && auth?.isAdmin) {
      api.usage().then(setUsage).catch(() => setError('無法更新用量統計'));
    }
  }, [roleView, auth?.isAdmin]);

  const riskSummary = useMemo(() => {
    const counts = { High: 0, Medium: 0, Low: 0 };
    findings.forEach((finding) => {
      if (finding.risk_level === 'High') counts.High += 1;
      if (finding.risk_level === 'Medium') counts.Medium += 1;
      if (finding.risk_level === 'Low') counts.Low += 1;
    });
    return counts;
  }, [findings]);

  async function handleUpload() {
    setError('');
    setBusy(true);
    setFindings([]);
    setJob(null);
    try {
      const result = await api.upload(selectedFiles);
      setJobId(result.jobId);
      setJob(await api.job(result.jobId));
    } catch (err) {
      setError(err instanceof Error ? err.message : '上傳失敗');
    } finally {
      setBusy(false);
    }
  }

  async function handleWebsiteScan() {
    setError('');
    setBusy(true);
    setFindings([]);
    setJob(null);
    try {
      const result = await api.scanWebsite({
        url: websiteUrl,
        mode: websiteMode,
        maxPages: websiteMaxPages,
        maxDepth: websiteMaxDepth,
        useSitemap: websiteUseSitemap,
        includePatterns: websiteMode === 'site' ? splitLines(websiteInclude) : [],
        excludePatterns: websiteMode === 'site' ? splitLines(websiteExclude) : [],
      });
      setJobId(result.jobId);
      setJob(await api.job(result.jobId));
    } catch (err) {
      setError(err instanceof Error ? err.message : '網站查驗失敗');
    } finally {
      setBusy(false);
    }
  }

  async function saveLimits() {
    if (!settings) return;
    const updated = await api.updateSettings(settings);
    setSettings(updated);
    setUsage(await api.usage());
    setError('成本控管設定已保存');
  }

  async function submitReview(decision: string) {
    if (!jobId) return;
    await api.review(jobId, decision, note);
    setNote('');
    setError('審核紀錄已保存');
  }

  async function cancelJob() {
    if (!jobId) return;
    try {
      await api.cancel(jobId);
      setJob(await api.job(jobId));
    } catch (err) {
      setError(err instanceof Error ? err.message : '取消任務失敗');
    }
  }

  async function saveAzureAiSettings() {
    if (!azureForm) return;
    try {
      const updated = await api.updateAzureAiSettings(azureForm);
      setAzureSettings(updated);
      setAzureForm({
        azureDocumentIntelligenceEndpoint: updated.azureDocumentIntelligenceEndpoint,
        azureDocumentIntelligenceKey: '',
        azureDocumentIntelligenceApiVersion: updated.azureDocumentIntelligenceApiVersion,
        azureLanguageEndpoint: updated.azureLanguageEndpoint,
        azureLanguageKey: '',
        azureLanguageApiVersion: updated.azureLanguageApiVersion,
        azureOpenAiEndpoint: updated.azureOpenAiEndpoint,
        azureOpenAiKey: '',
        azureOpenAiDeployment: updated.azureOpenAiDeployment,
        azureOpenAiApiVersion: updated.azureOpenAiApiVersion,
      });
      setError('Azure AI 設定已保存，新的查驗任務會使用更新後設定');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Azure AI 設定保存失敗');
    }
  }

  async function saveWhitelist() {
    if (!whitelist) return;
    try {
      setWhitelist(await api.updateWhitelist(whitelist.config));
      setError('白名單已保存，後續網站查驗會立即套用');
    } catch (err) {
      setError(err instanceof Error ? err.message : '白名單保存失敗');
    }
  }

  async function testAzureAiConnection(service: AzureAiService) {
    setTestingAzureService(service);
    setAzureTestResults((results) => ({ ...results, [service]: undefined }));
    try {
      const result = await api.testAzureAiService(service);
      setAzureTestResults((results) => ({ ...results, [service]: { tone: 'ok', message: result.message } }));
    } catch (err) {
      setAzureTestResults((results) => ({
        ...results,
        [service]: { tone: 'error', message: err instanceof Error ? err.message : 'Azure AI 連線測試失敗' },
      }));
    } finally {
      setTestingAzureService(null);
    }
  }

  if (!auth) {
    return (
      <main className="login-page">
        <Loader2 className="spin" size={26} />
        <p>正在檢查登入狀態</p>
      </main>
    );
  }

  if (auth.authRequired && !auth.authenticated) {
    return (
      <main className="login-page">
        <section className="login-panel">
          <ShieldCheck size={42} />
          <h1>個資查驗系統</h1>
          <p>請使用學校 Microsoft 365 帳號登入後，再上傳公開網站檔案進行查驗。</p>
          {!auth.authConfigured && (
            <div className="notice">尚未設定 Microsoft Entra 應用程式參數，請先設定 App Service 環境變數。</div>
          )}
          <a className="report-link" href="/auth/login">使用 Microsoft 365 登入</a>
        </section>
      </main>
    );
  }

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <ShieldCheck size={30} />
          <div>
            <h1>個資查驗</h1>
            <p>公開網站上傳前審查</p>
          </div>
        </div>
        <nav>
          <button className={roleView === 'user' ? 'active' : ''} onClick={() => setRoleView('user')}>
            <FileSearch size={18} /> 查驗工作台
          </button>
          {auth.isAdmin && (
            <button className={roleView === 'admin' ? 'active' : ''} onClick={() => setRoleView('admin')}>
              <ShieldCheck size={18} /> 管理後台
            </button>
          )}
        </nav>
      </aside>

      <section className="content">
        <header className="topbar">
          <div>
            <h2>{roleView === 'admin' ? '系統管理後台' : '檔案查驗工作台'}</h2>
            <p>
              {roleView === 'admin'
                ? '調整上傳限制與 Azure AI 服務連線設定。'
                : '原始檔只暫存處理，完成後只保留遮罩後結果與審核紀錄。'}
            </p>
          </div>
          <div className="user-actions">
            <span>{auth.user?.name || auth.user?.email || '本機模式'}</span>
            {auth.isAdmin && (
              <div className="role-switch" aria-label="檢視角色">
                <button className={roleView === 'user' ? 'active' : ''} onClick={() => setRoleView('user')}>
                  <UserRound size={16} /> 一般使用者
                </button>
                <button className={roleView === 'admin' ? 'active' : ''} onClick={() => setRoleView('admin')}>
                  <ShieldCheck size={16} /> 管理者
                </button>
              </div>
            )}
            {roleView === 'user' && jobId && (
              <div className="report-downloads" aria-label="下載查驗報告">
                <a className="report-link" href={`/api/jobs/${jobId}/report.pdf`}>下載 PDF</a>
                <a className="report-link" href={`/api/jobs/${jobId}/report.xlsx`}>下載 Excel</a>
                <a className="icon-link" href={`/api/jobs/${jobId}/report`}>JSON</a>
              </div>
            )}
            {auth.authRequired && <a className="icon-link" href="/auth/logout"><LogOut size={18} />登出</a>}
          </div>
        </header>

        {error && <div className="notice">{error}</div>}

        {roleView === 'user' && (
          <div className="advisory">
            <AlertTriangle size={18} />
            <p>本系統僅為<strong>輔助查驗</strong>工具，可能有漏判或誤判。承辦人員仍須自行仔細查驗，並對最終結果負責。</p>
          </div>
        )}

        {roleView === 'user' && <section className="grid user-workspace-grid">
          <div className="panel upload-panel">
            <div className="panel-title">
              {scanSource === 'file' ? <UploadCloud size={22} /> : <Globe2 size={22} />}
              <h3>{scanSource === 'file' ? '上傳查驗' : '網站查驗'}</h3>
              {scanSource === 'website' && <span className="status-badge developing">開發中</span>}
            </div>
            <div className="mode-switch" aria-label="查驗來源">
              <button className={scanSource === 'file' ? 'active' : ''} onClick={() => setScanSource('file')}>
                <UploadCloud size={16} /> 檔案
              </button>
              <button className={scanSource === 'website' ? 'active' : ''} onClick={() => setScanSource('website')}>
                <Globe2 size={16} /> 網站
              </button>
            </div>
            {scanSource === 'file' ? (
              <>
                <label className="dropzone">
                  <input
                    type="file"
                    multiple
                    onChange={(event) => setSelectedFiles(Array.from(event.target.files || []))}
                  />
                  <span>選擇 PDF、Office、CSV、TXT 或圖片</span>
                  <small>
                    單檔 {settings?.maxFileMb ?? 25} MB，單次 {settings?.maxFilesPerUpload ?? 5} 個檔案
                  </small>
                </label>
                <div className="file-list">
                  {selectedFiles.map((file) => (
                    <div key={file.name}>
                      <span>{file.name}</span>
                      <strong>{(file.size / 1024 / 1024).toFixed(2)} MB</strong>
                    </div>
                  ))}
                </div>
                {usageEstimate && (
                  <div className="estimate-box">
                    <strong>本次預估用量</strong>
                    <span>OCR {usageEstimate.ocrPages.toLocaleString()} 頁</span>
                    <span>Language {usageEstimate.languageRecords.toLocaleString()} records</span>
                    <span>GPT {usageEstimate.openAiTokens.toLocaleString()} tokens</span>
                  </div>
                )}
                {estimateErrors.length > 0 && <p className="quota-error">{estimateErrors.join(' ')}</p>}
                <button disabled={!selectedFiles.length || busy || estimateErrors.length > 0} onClick={handleUpload}>
                  {busy ? <Loader2 className="spin" size={18} /> : <UploadCloud size={18} />}
                  開始查驗
                </button>
              </>
            ) : (
              <div className="website-form">
                <div className="feature-callout">
                  <div>
                    <span className="status-badge developing">網站掃描功能開發中</span>
                    <strong>目前適合用來輔助抽查公開網頁，正式公開前仍須人工複核。</strong>
                  </div>
                  <p>
                    此功能會抓取公開網址文字與可辨識文件連結進行個資風險檢查。整站掃描仍在調整效能、覆蓋率與誤判控管，
                    建議先以單一網址或小範圍目錄測試。
                  </p>
                </div>
                <div className="mode-switch compact-switch" aria-label="網站查驗模式">
                  <button className={websiteMode === 'url' ? 'active' : ''} onClick={() => setWebsiteMode('url')}>單一網址</button>
                  <button className={websiteMode === 'site' ? 'active' : ''} onClick={() => setWebsiteMode('site')}>整站掃描</button>
                </div>
                <label>
                  公開網站網址
                  <div className="input-with-icon"><Link size={17} /><input value={websiteUrl} onChange={(event) => setWebsiteUrl(event.target.value)} placeholder="https://www.example.edu.tw/" /></div>
                </label>
                {websiteMode === 'site' && (
                  <div className="website-options">
                    <label>最多頁數<input type="number" min="1" max="30" value={websiteMaxPages} onChange={(event) => setWebsiteMaxPages(Number(event.target.value))} /></label>
                    <label>連結深度<input type="number" min="0" max="2" value={websiteMaxDepth} onChange={(event) => setWebsiteMaxDepth(Number(event.target.value))} /></label>
                    <label className="check-row"><input type="checkbox" checked={websiteUseSitemap} onChange={(event) => setWebsiteUseSitemap(event.target.checked)} /> 使用 sitemap.xml 擴充掃描範圍</label>
                    <label className="field-label">
                      只掃描（include，每行一條，可用關鍵字或正則）
                      <textarea value={websiteInclude} onChange={(event) => setWebsiteInclude(event.target.value)} placeholder={'/news/\n/announcement/'} />
                    </label>
                    <label className="field-label">
                      排除（exclude，每行一條，優先於 include）
                      <textarea value={websiteExclude} onChange={(event) => setWebsiteExclude(event.target.value)} placeholder={'/login\n/admin'} />
                    </label>
                  </div>
                )}
                <p className="form-note">只掃描公開網址；整站模式限制同網域並遵守 robots.txt。</p>
                <div className="website-capabilities" aria-label="網站掃描目前使用方式與能力">
                  <section>
                    <h4>建議使用方式</h4>
                    <ul>
                      <li>先用「單一網址」檢查公告、表單、名冊、活動成果頁等高風險頁面。</li>
                      <li>整站掃描請先限制最多頁數、連結深度，並用 include / exclude 縮小到特定目錄。</li>
                      <li>若掃描時間較長，請觀察任務狀態的耗時與最近活動；必要時可取消後調低頁數再試。</li>
                    </ul>
                  </section>
                  <section>
                    <h4>目前能力</h4>
                    <ul>
                      <li>支援 http / https 公開網址，會阻擋本機與內部網路位址。</li>
                      <li>單一網址會擷取頁面文字，套用個資規則、白名單與遮罩後結果。</li>
                      <li>整站模式限制同網域，可遵守 robots.txt、讀取 sitemap.xml，並記錄已掃頁數與略過原因。</li>
                      <li>可偵測頁面中的身分證、電話、Email、地址、護照、健保卡、車牌、IP 等常見風險。</li>
                    </ul>
                  </section>
                  <section>
                    <h4>目前限制</h4>
                    <ul>
                      <li>不登入後台、不掃描需要帳號密碼、表單送出或互動後才出現的內容。</li>
                      <li>動態載入內容、圖片文字與大型附件可能仍需人工或檔案查驗補強。</li>
                      <li>整站掃描可能受網站速度、robots.txt、連結結構與 Azure AI 回應時間影響。</li>
                    </ul>
                  </section>
                </div>
                <button disabled={!websiteUrl.trim() || busy} onClick={handleWebsiteScan}>
                  {busy ? <Loader2 className="spin" size={18} /> : <Globe2 size={18} />}
                  開始網站查驗
                </button>
              </div>
            )}
          </div>

          <div className="panel">
            <div className="panel-title">
              <FileSearch size={22} />
              <h3>任務狀態</h3>
            </div>
            {job ? (
              <>
                <div className="progress-row">
                  <span>{job.message || job.status}</span>
                  <strong>{job.progress}%</strong>
                </div>
                <div className="progress"><span style={{ width: `${job.progress}%` }} /></div>
                <div className="activity-row">
                  <span>已耗時 {formatDuration(clock - new Date(job.created_at).getTime())}</span>
                  <span>最近活動 {formatDuration(clock - new Date(job.updated_at).getTime())} 前</span>
                </div>
                {!isTerminalStatus(job.status) && clock - new Date(job.updated_at).getTime() > 45000 && (
                  <p className="slow-notice">外部 AI 服務回應較慢，系統仍在等待。可繼續等候或取消任務後再試。</p>
                )}
                {job.scanMeta && <WebsiteProgress meta={job.scanMeta} />}
                <div className="status-cards">
                  <Metric label="整體風險" value={job.risk_level} tone={riskTone(job.risk_level)} />
                  <Metric label="高風險" value={riskSummary.High.toString()} tone="high" />
                  <Metric label="中風險" value={riskSummary.Medium.toString()} tone="medium" />
                </div>
                <div className="file-list compact">
                  {job.files.map((file) => (
                    <div key={file.id}>
                      <span>{file.original_name}</span>
                      <strong>{file.error || file.status}</strong>
                    </div>
                  ))}
                </div>
                {job.scanMeta && <ScanMetaView meta={job.scanMeta} />}
                {['queued', 'processing', 'cancelling'].includes(job.status) && (
                  <button className="secondary-button" onClick={cancelJob} disabled={job.status === 'cancelling'}>
                    <CircleStop size={18} /> {job.status === 'cancelling' ? '正在取消' : '取消任務'}
                  </button>
                )}
              </>
            ) : (
              <p className="empty">尚未建立查驗任務。</p>
            )}
          </div>

        </section>}

        {roleView === 'admin' && auth.isAdmin && usage && <section className="usage-grid">
          <UsageCard label="本日個人查驗" metric={{ used: usage.today.userJobs, limit: usage.dailyUserJobLimit, remaining: Math.max(0, usage.dailyUserJobLimit - usage.today.userJobs) }} unit="次" />
          <UsageCard label="本月 OCR" metric={usage.monthly.ocrPages} unit="頁" />
          <UsageCard label="本月 Language" metric={usage.monthly.languageRecords} unit="records" />
          <UsageCard label="本月 GPT" metric={usage.monthly.openAiTokens} unit="tokens" />
        </section>}

        {roleView === 'admin' && auth.isAdmin && <section className="admin-workspace">
          <div className="panel settings-panel">
            <div className="panel-title">
              <Settings size={22} />
              <h3>配額與服務控管</h3>
            </div>
            <label>
              單檔 MB
              <input
                type="number"
                min="1"
                value={settings?.maxFileMb ?? 25}
                onChange={(event) => settings && setSettings({ ...settings, maxFileMb: Number(event.target.value) })}
              />
            </label>
            <label>
              單次檔案數
              <input
                type="number"
                min="1"
                value={settings?.maxFilesPerUpload ?? 5}
                onChange={(event) => settings && setSettings({ ...settings, maxFilesPerUpload: Number(event.target.value) })}
              />
            </label>
            <label>
              每位使用者每日查驗次數
              <input type="number" min="1" value={settings?.dailyUserJobLimit ?? 30} onChange={(event) => settings && setSettings({ ...settings, dailyUserJobLimit: Number(event.target.value) })} />
            </label>
            <label>
              每月 OCR 頁數
              <input type="number" min="0" value={settings?.monthlyOcrPageLimit ?? 10000} onChange={(event) => settings && setSettings({ ...settings, monthlyOcrPageLimit: Number(event.target.value) })} />
            </label>
            <label>
              每月 Language Text Records
              <input type="number" min="0" value={settings?.monthlyLanguageRecordLimit ?? 10000} onChange={(event) => settings && setSettings({ ...settings, monthlyLanguageRecordLimit: Number(event.target.value) })} />
            </label>
            <label>
              每月 GPT Token
              <input type="number" min="0" value={settings?.monthlyOpenAiTokenLimit ?? 1000000} onChange={(event) => settings && setSettings({ ...settings, monthlyOpenAiTokenLimit: Number(event.target.value) })} />
            </label>
            <div className="switch-list">
              <Toggle label="OCR 服務" checked={settings?.documentIntelligenceEnabled ?? true} onChange={(checked) => settings && setSettings({ ...settings, documentIntelligenceEnabled: checked })} />
              <Toggle label="Language PII 服務" checked={settings?.languagePiiEnabled ?? true} onChange={(checked) => settings && setSettings({ ...settings, languagePiiEnabled: checked })} />
              <Toggle label="GPT 語意分析" checked={settings?.openAiEnabled ?? true} onChange={(checked) => settings && setSettings({ ...settings, openAiEnabled: checked })} />
              <Toggle label="GPT 僅於已有風險時啟用" checked={settings?.openAiEscalationOnly ?? true} onChange={(checked) => settings && setSettings({ ...settings, openAiEscalationOnly: checked })} />
            </div>
            <button onClick={saveLimits}><CheckCircle2 size={18} /> 保存成本控管</button>
          </div>
        </section>}

        {roleView === 'admin' && auth.isAdmin && azureForm && (
          <section className="panel admin-panel">
            <div className="panel-title">
              <KeyRound size={22} />
              <h3>Azure AI 連線設定</h3>
            </div>
            <div className="admin-grid">
              <SecretGroup
                title="Azure AI 文件智慧服務 OCR"
                endpointLabel="Endpoint"
                endpoint={azureForm.azureDocumentIntelligenceEndpoint}
                onEndpoint={(value) => setAzureForm({ ...azureForm, azureDocumentIntelligenceEndpoint: value })}
                keyValue={azureForm.azureDocumentIntelligenceKey}
                onKey={(value) => setAzureForm({ ...azureForm, azureDocumentIntelligenceKey: value })}
                keyStatus={azureSettings?.azureDocumentIntelligenceKey}
                versionLabel="API version"
                version={azureForm.azureDocumentIntelligenceApiVersion}
                onVersion={(value) => setAzureForm({ ...azureForm, azureDocumentIntelligenceApiVersion: value })}
                onTest={() => testAzureAiConnection('documentIntelligence')}
                testing={testingAzureService === 'documentIntelligence'}
                testResult={azureTestResults.documentIntelligence}
              />
              <SecretGroup
                title="Azure AI Language PII"
                endpointLabel="Endpoint"
                endpoint={azureForm.azureLanguageEndpoint}
                onEndpoint={(value) => setAzureForm({ ...azureForm, azureLanguageEndpoint: value })}
                keyValue={azureForm.azureLanguageKey}
                onKey={(value) => setAzureForm({ ...azureForm, azureLanguageKey: value })}
                keyStatus={azureSettings?.azureLanguageKey}
                versionLabel="API version"
                version={azureForm.azureLanguageApiVersion}
                onVersion={(value) => setAzureForm({ ...azureForm, azureLanguageApiVersion: value })}
                onTest={() => testAzureAiConnection('language')}
                testing={testingAzureService === 'language'}
                testResult={azureTestResults.language}
              />
              <SecretGroup
                title="Azure OpenAI"
                endpointLabel="Endpoint"
                endpoint={azureForm.azureOpenAiEndpoint}
                onEndpoint={(value) => setAzureForm({ ...azureForm, azureOpenAiEndpoint: value })}
                keyValue={azureForm.azureOpenAiKey}
                onKey={(value) => setAzureForm({ ...azureForm, azureOpenAiKey: value })}
                keyStatus={azureSettings?.azureOpenAiKey}
                versionLabel="API version"
                version={azureForm.azureOpenAiApiVersion}
                onVersion={(value) => setAzureForm({ ...azureForm, azureOpenAiApiVersion: value })}
                onTest={() => testAzureAiConnection('openAi')}
                testing={testingAzureService === 'openAi'}
                testResult={azureTestResults.openAi}
              >
                <label>
                  Deployment
                  <input
                    value={azureForm.azureOpenAiDeployment}
                    onChange={(event) => setAzureForm({ ...azureForm, azureOpenAiDeployment: event.target.value })}
                    placeholder="gpt-5-mini"
                  />
                </label>
              </SecretGroup>
            </div>
            <div className="admin-actions">
              <p>API key 不會明文顯示；空白欄位代表保留既有 key。</p>
              <button onClick={saveAzureAiSettings}><CheckCircle2 size={18} /> 保存 Azure AI 設定</button>
            </div>
          </section>
        )}

        {roleView === 'admin' && auth.isAdmin && whitelist && (
          <section className="panel admin-panel whitelist-panel">
            <div className="panel-title">
              <ListFilter size={22} />
              <h3>網站掃描白名單</h3>
            </div>
            <p className="form-note">白名單只影響後續網站掃描。勾選代表停用該偵測器；忽略詞命中值或上下文時不列入結果。</p>
            <label className="field-label">
              全域忽略詞
              <textarea
                value={whitelist.config.ignore_words.join('\n')}
                onChange={(event) => setWhitelist({
                  ...whitelist,
                  config: { ...whitelist.config, ignore_words: splitLines(event.target.value) },
                })}
                placeholder={'淡江大學\npublic@example.com'}
              />
            </label>
            <DetectorGrid
              detectors={whitelist.detectors}
              selected={whitelist.config.global_disabled_detectors}
              onChange={(selected) => setWhitelist({
                ...whitelist,
                config: { ...whitelist.config, global_disabled_detectors: selected },
              })}
            />
            <div className="domain-rule-list">
              {whitelist.config.domain_rules.map((rule, index) => (
                <div className="domain-rule" key={index}>
                  <div className="domain-rule-title">
                    <strong>網域規則 #{index + 1}</strong>
                    <button className="icon-button" title="刪除網域規則" onClick={() => setWhitelist({
                      ...whitelist,
                      config: {
                        ...whitelist.config,
                        domain_rules: whitelist.config.domain_rules.filter((_, ruleIndex) => ruleIndex !== index),
                      },
                    })}><Trash2 size={17} /></button>
                  </div>
                  <label className="field-label">
                    網域
                    <input value={rule.domain} onChange={(event) => updateDomainRule(whitelist, setWhitelist, index, { domain: event.target.value })} placeholder="tku.edu.tw" />
                  </label>
                  <label className="field-label">
                    此網域忽略詞
                    <textarea value={rule.ignore_words.join('\n')} onChange={(event) => updateDomainRule(whitelist, setWhitelist, index, { ignore_words: splitLines(event.target.value) })} />
                  </label>
                  <DetectorGrid detectors={whitelist.detectors} selected={rule.disabled_detectors} onChange={(selected) => updateDomainRule(whitelist, setWhitelist, index, { disabled_detectors: selected })} />
                </div>
              ))}
            </div>
            <div className="admin-actions">
              <button className="secondary-button" onClick={() => setWhitelist({
                ...whitelist,
                config: {
                  ...whitelist.config,
                  domain_rules: [...whitelist.config.domain_rules, { domain: '', disabled_detectors: [], ignore_words: [] }],
                },
              })}><Plus size={18} /> 新增網域規則</button>
              <button onClick={saveWhitelist}><CheckCircle2 size={18} /> 保存白名單</button>
            </div>
          </section>
        )}

        {roleView === 'user' && <section className="panel findings-panel">
          <div className="panel-title">
            <AlertTriangle size={22} />
            <h3>風險發現</h3>
          </div>
          {findings.length > 0 && job?.scanMeta?.mode && <WebsiteFindingGroups findings={findings} />}
          {findings.length > 0 && !job?.scanMeta?.mode && <SourceSummary findings={findings} />}
          <div className="findings-table">
            <div className="table-head">
              <span>風險</span><span>檔案</span><span>類型</span><span>遮罩內容</span><span>位置</span><span>建議</span>
            </div>
            {findings.length === 0 ? (
              <p className="empty">查驗完成後會顯示遮罩後的疑似個資。</p>
            ) : findings.map((finding) => (
              <div className="table-row" key={finding.id}>
                <span className={`risk ${finding.risk_level.toLowerCase()}`}>{finding.risk_level}</span>
                <span>{finding.original_name}</span>
                <span>{finding.category}</span>
                <span>{finding.masked_text}</span>
                <span>{finding.location}</span>
                <span>{finding.recommendation}</span>
              </div>
            ))}
          </div>
          <div className="review-bar">
            <input value={note} onChange={(event) => setNote(event.target.value)} placeholder="審核備註" />
            <button onClick={() => submitReview('approved')}>通過</button>
            <button onClick={() => submitReview('needs_changes')}>需修改</button>
            <button onClick={() => submitReview('false_positive')}>誤判</button>
            <button onClick={() => submitReview('approved_after_redaction')}>遮罩後通過</button>
          </div>
        </section>}
      </section>
    </main>
  );
}

function Metric({ label, value, tone }: { label: string; value: string; tone: string }) {
  return (
    <div className={`metric ${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (!bytes) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function WebsiteProgress({ meta }: { meta: ScanMeta }) {
  const stats = meta.stats || {};
  if (!stats.current_url && !stats.pages_scanned && !stats.queue_size) return null;
  const scanned = stats.pages_scanned ?? 0;
  const maxPages = stats.max_pages ?? (meta.mode === 'site' ? 0 : 1);
  return (
    <div className="website-progress-detail">
      <div>
        <span>已掃頁數</span>
        <strong>{maxPages ? `${scanned} / ${maxPages}` : scanned}</strong>
      </div>
      <div>
        <span>佇列剩餘</span>
        <strong>{stats.queue_size ?? 0}</strong>
      </div>
      {stats.current_url && (
        <div className="current-url">
          <span>目前 URL</span>
          <strong title={stats.current_url}>{stats.current_url}</strong>
        </div>
      )}
    </div>
  );
}

function ScanMetaView({ meta }: { meta: ScanMeta }) {
  const stats = meta.stats || {};
  const chips: Array<[string, string]> = [];
  if (meta.mode === 'site') {
    chips.push(['頁面', String(stats.pages_scanned ?? 0)]);
    if (stats.html_scanned) chips.push(['HTML', String(stats.html_scanned)]);
    if (stats.documents_scanned) chips.push(['文件', String(stats.documents_scanned)]);
    if (stats.archives_scanned) chips.push(['壓縮包', String(stats.archives_scanned)]);
    if (stats.text_scanned) chips.push(['文字檔', String(stats.text_scanned)]);
    if (stats.sitemap_seeded) chips.push(['sitemap', String(stats.sitemap_seeded)]);
    if (stats.bytes_total) chips.push(['傳輸量', formatBytes(stats.bytes_total)]);
  }
  const assets = [
    ...(stats.document_urls || []).map((item) => ({ ...item, kind: '文件' })),
    ...(stats.archive_urls || []).map((item) => ({ ...item, kind: '壓縮包' })),
    ...(stats.text_urls || []).map((item) => ({ ...item, kind: '文字' })),
  ];
  const skipped = stats.skipped_urls || [];
  return (
    <div className="scan-meta">
      {chips.length > 0 && (
        <div className="scan-stats">
          {chips.map(([label, value]) => (
            <span key={label}><em>{label}</em>{value}</span>
          ))}
        </div>
      )}
      {(assets.length > 0 || skipped.length > 0) && (
        <details className="asset-status" open>
          <summary>附件與網址處理狀態（已處理 {assets.length}，略過 {skipped.length}）</summary>
          <div className="asset-rows">
            {assets.map((asset) => (
              <div className="asset-row" key={`${asset.kind}-${asset.url}`}>
                <span className="asset-kind">{asset.kind}{asset.type ? ` ${asset.type}` : ''}</span>
                <span className="asset-url" title={asset.url}>{asset.url}</span>
                <strong>{asset.bytes ? formatBytes(asset.bytes) : asset.status}</strong>
              </div>
            ))}
            {skipped.map((item) => (
              <div className="asset-row skipped" key={`skipped-${item.url}`}>
                <span className="asset-kind">略過</span>
                <span className="asset-url" title={item.url}>{item.url}</span>
                <strong>{item.reason}</strong>
              </div>
            ))}
          </div>
        </details>
      )}
      {meta.issues.length > 0 && (
        <details className="scan-issues">
          <summary>掃描過程問題 {meta.issues.length} 筆</summary>
          <ul>
            {meta.issues.map((issue, index) => (
              <li key={index}><span className="issue-path">{issue.path}</span> — {issue.reason}</li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}

function findingSource(finding: Finding): string {
  return (finding.location || finding.original_name || '未知來源').split('#')[0];
}

function WebsiteFindingGroups({ findings }: { findings: Finding[] }) {
  const groups = new Map<string, Finding[]>();
  findings.forEach((finding) => {
    const source = findingSource(finding);
    groups.set(source, [...(groups.get(source) || []), finding]);
  });
  const rows = Array.from(groups.entries()).sort((a, b) => {
    const highA = a[1].filter((finding) => finding.risk_level === 'High').length;
    const highB = b[1].filter((finding) => finding.risk_level === 'High').length;
    return highB - highA || b[1].length - a[1].length;
  });
  return (
    <div className="website-finding-groups">
      {rows.map(([source, sourceFindings]) => {
        const high = sourceFindings.filter((finding) => finding.risk_level === 'High').length;
        const medium = sourceFindings.filter((finding) => finding.risk_level === 'Medium').length;
        const low = sourceFindings.length - high - medium;
        return (
          <details className="website-finding-group" key={source} open={rows.length <= 3}>
            <summary>
              <span title={source}>{source}</span>
              <em>
                {high > 0 && <b className="risk high">高 {high}</b>}
                {medium > 0 && <b className="risk medium">中 {medium}</b>}
                {low > 0 && <b className="risk low">低 {low}</b>}
              </em>
            </summary>
            <div className="group-finding-list">
              {sourceFindings.map((finding) => (
                <div className="group-finding" key={finding.id}>
                  <span className={`risk ${finding.risk_level.toLowerCase()}`}>{finding.risk_level}</span>
                  <span>{finding.category}</span>
                  <strong>{finding.masked_text}</strong>
                  <span>{finding.location}</span>
                  <span>{finding.recommendation}</span>
                </div>
              ))}
            </div>
          </details>
        );
      })}
    </div>
  );
}

function SourceSummary({ findings }: { findings: Finding[] }) {
  const groups = new Map<string, { high: number; medium: number; low: number; total: number }>();
  findings.forEach((finding) => {
    // location 含頁面 URL 或檔名（可能帶 #page/工作表），取 # 前作為來源
    const source = findingSource(finding);
    const group = groups.get(source) || { high: 0, medium: 0, low: 0, total: 0 };
    if (finding.risk_level === 'High') group.high += 1;
    else if (finding.risk_level === 'Medium') group.medium += 1;
    else group.low += 1;
    group.total += 1;
    groups.set(source, group);
  });
  if (groups.size <= 1) return null;
  const rows = Array.from(groups.entries()).sort((a, b) => b[1].high - a[1].high || b[1].total - a[1].total);
  return (
    <details className="source-summary" open>
      <summary>依來源彙整（{groups.size} 個頁面/檔案）</summary>
      <div className="source-rows">
        {rows.map(([source, counts]) => (
          <div className="source-row" key={source}>
            <span className="source-name" title={source}>{source}</span>
            <span className="source-counts">
              {counts.high > 0 && <em className="risk high">高 {counts.high}</em>}
              {counts.medium > 0 && <em className="risk medium">中 {counts.medium}</em>}
              {counts.low > 0 && <em className="risk low">低 {counts.low}</em>}
            </span>
          </div>
        ))}
      </div>
    </details>
  );
}

function UsageCard({ label, metric, unit }: { label: string; metric: UsageMetric; unit: string }) {
  const percent = metric.limit > 0 ? Math.min(100, Math.round(metric.used / metric.limit * 100)) : 100;
  return (
    <div className="panel usage-card">
      <div className="usage-title"><Gauge size={18} /><strong>{label}</strong></div>
      <span>已用 {metric.used.toLocaleString()} / {metric.limit.toLocaleString()} {unit}</span>
      <div className="progress"><span style={{ width: `${percent}%` }} /></div>
      <small>剩餘 {metric.remaining.toLocaleString()} {unit}</small>
    </div>
  );
}

function Toggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: (checked: boolean) => void }) {
  return (
    <label className="toggle-row">
      <span>{label}</span>
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} />
      <i aria-hidden="true" />
    </label>
  );
}

function DetectorGrid({ detectors, selected, onChange }: { detectors: string[]; selected: string[]; onChange: (selected: string[]) => void }) {
  return (
    <div className="detector-grid">
      {detectors.map((detector) => (
        <label key={detector}>
          <input
            type="checkbox"
            checked={selected.includes(detector)}
            onChange={(event) => onChange(event.target.checked ? [...selected, detector] : selected.filter((item) => item !== detector))}
          />
          停用 {DETECTOR_LABELS[detector] || detector}
        </label>
      ))}
    </div>
  );
}

function updateDomainRule(whitelist: WhitelistState, setWhitelist: (state: WhitelistState) => void, index: number, update: Partial<DomainRule>) {
  setWhitelist({
    ...whitelist,
    config: {
      ...whitelist.config,
      domain_rules: whitelist.config.domain_rules.map((rule, ruleIndex) => ruleIndex === index ? { ...rule, ...update } : rule),
    },
  });
}

function splitLines(value: string) {
  return value.split('\n').map((item) => item.trim()).filter(Boolean);
}

const DETECTOR_LABELS: Record<string, string> = {
  surname_name: '百家姓全文',
  chinese_name: '關鍵字姓名',
  taiwan_address: '台灣地址',
  taiwan_id: '身分證',
  taiwan_mobile: '手機',
  email: 'Email',
  ipv4: 'IPv4',
  taiwan_landline: '市話',
  credit_card: '信用卡',
  taiwan_business_id: '統編',
  taiwan_passport: '護照',
  taiwan_nhi_card: '健保卡',
  bank_account: '銀行帳號',
  date_of_birth: '生日',
  taiwan_license_plate: '車牌',
  ipv6: 'IPv6',
  taiwan_resident_cert: '居留證',
};

function SecretGroup({
  title,
  endpointLabel,
  endpoint,
  onEndpoint,
  keyValue,
  onKey,
  keyStatus,
  versionLabel,
  version,
  onVersion,
  onTest,
  testing,
  testResult,
  children,
}: {
  title: string;
  endpointLabel: string;
  endpoint: string;
  onEndpoint: (value: string) => void;
  keyValue: string;
  onKey: (value: string) => void;
  keyStatus?: SecretStatus;
  versionLabel: string;
  version: string;
  onVersion: (value: string) => void;
  onTest: () => void;
  testing: boolean;
  testResult?: AzureAiTestResult;
  children?: ReactNode;
}) {
  return (
    <fieldset className="secret-group">
      <legend>{title}</legend>
      <label>
        {endpointLabel}
        <input value={endpoint} onChange={(event) => onEndpoint(event.target.value)} placeholder="https://..." />
      </label>
      <label>
        API key
        <input
          type="password"
          value={keyValue}
          onChange={(event) => onKey(event.target.value)}
          placeholder={keyStatus?.configured ? `已設定：${keyStatus.masked}` : '尚未設定'}
          autoComplete="off"
        />
      </label>
      <label>
        {versionLabel}
        <input value={version} onChange={(event) => onVersion(event.target.value)} />
      </label>
      {children}
      <button className="secondary-button" onClick={onTest} disabled={testing}>
        {testing ? <Loader2 className="spin" size={18} /> : <PlugZap size={18} />}
        {testing ? '正在測試' : '測試連線'}
      </button>
      {testResult && <p className={`connection-result ${testResult.tone}`}>{testResult.message}</p>}
    </fieldset>
  );
}

function riskTone(risk: string) {
  if (risk === 'High') return 'high';
  if (risk === 'Medium') return 'medium';
  if (risk === 'Low') return 'low';
  return 'none';
}

function isTerminalStatus(status: string) {
  return ['completed', 'failed', 'cancelled', 'timed_out'].includes(status);
}

function formatDuration(milliseconds: number) {
  const seconds = Math.max(0, Math.floor(milliseconds / 1000));
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  return minutes ? `${minutes} 分 ${remainder} 秒` : `${remainder} 秒`;
}

createRoot(document.getElementById('root')!).render(<App />);
