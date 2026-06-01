import { useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { AlertTriangle, CheckCircle2, CircleStop, FileSearch, KeyRound, Loader2, LogOut, PlugZap, Settings, ShieldCheck, UploadCloud } from 'lucide-react';
import { createRoot } from 'react-dom/client';
import './styles.css';

type Job = {
  id: string;
  status: string;
  progress: number;
  message: string | null;
  risk_level: string;
  created_at: string;
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

  useEffect(() => {
    api.me()
      .then((state) => {
        setAuth(state);
        if (state.authenticated || !state.authRequired) {
          return Promise.all([
            api.settings().then(setSettings),
            state.isAdmin ? api.azureAiSettings().then((config) => {
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
    if (!jobId) return;
    const timer = window.setInterval(async () => {
      const nextJob = await api.job(jobId);
      setJob(nextJob);
      if (nextJob.status === 'completed' || nextJob.status === 'failed') {
        const data = await api.findings(jobId);
        setFindings(data.items || []);
        window.clearInterval(timer);
      }
    }, 1200);
    return () => window.clearInterval(timer);
  }, [jobId]);

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

  async function saveLimit() {
    if (!settings) return;
    const updated = await api.updateSettings({
      maxFileMb: settings.maxFileMb,
      maxFilesPerUpload: settings.maxFilesPerUpload,
    });
    setSettings(updated);
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
          <a className="active"><FileSearch size={18} /> 查驗工作台</a>
          <a><Settings size={18} /> 系統限制</a>
          {auth.isAdmin && <a><KeyRound size={18} /> Azure AI 金鑰</a>}
        </nav>
      </aside>

      <section className="content">
        <header className="topbar">
          <div>
            <h2>檔案查驗工作台</h2>
            <p>原始檔只暫存處理，完成後只保留遮罩後結果與審核紀錄。</p>
          </div>
          <div className="user-actions">
            <span>{auth.user?.name || auth.user?.email || '本機模式'}</span>
            <a className="report-link" href={jobId ? `/api/jobs/${jobId}/report` : '#'}>下載報告 JSON</a>
            {auth.authRequired && <a className="icon-link" href="/auth/logout"><LogOut size={18} />登出</a>}
          </div>
        </header>

        {error && <div className="notice">{error}</div>}

        <section className="grid">
          <div className="panel upload-panel">
            <div className="panel-title">
              <UploadCloud size={22} />
              <h3>上傳查驗</h3>
            </div>
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
            <button disabled={!selectedFiles.length || busy} onClick={handleUpload}>
              {busy ? <Loader2 className="spin" size={18} /> : <UploadCloud size={18} />}
              開始查驗
            </button>
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

          <div className="panel settings-panel">
            <div className="panel-title">
              <Settings size={22} />
              <h3>上傳限制</h3>
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
            <button onClick={saveLimit}><CheckCircle2 size={18} /> 保存限制</button>
          </div>
        </section>

        {auth.isAdmin && azureForm && (
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

        <section className="panel findings-panel">
          <div className="panel-title">
            <AlertTriangle size={22} />
            <h3>風險發現</h3>
          </div>
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
        </section>
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

createRoot(document.getElementById('root')!).render(<App />);
