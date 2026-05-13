import { useEffect, useState } from "react";
import axios from "axios";
import {
  Activity,
  AlertTriangle,
  Database,
  ExternalLink,
  FileText,
  FileUp,
  RefreshCw,
  Server,
  ShieldAlert,
  Siren,
  TerminalSquare,
} from "lucide-react";
import "@/App.css";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = BACKEND_URL;

const statusColor = {
  critical: "bg-red-500 text-white border-red-400",
  high: "bg-orange-500 text-black border-orange-300",
  medium: "bg-yellow-400 text-black border-yellow-200",
  low: "bg-green-500 text-black border-green-300",
};

function MetricCard({ testId, icon: Icon, label, value, detail }) {
  return (
    <section
      data-testid={testId}
      className="rounded-sm border border-zinc-800 bg-zinc-900 p-5 transition-colors duration-200 hover:bg-zinc-900/70"
    >
      <div className="flex items-center justify-between gap-3">
        <p data-testid={`${testId}-label`} className="text-xs uppercase tracking-[0.2em] text-zinc-500">
          {label}
        </p>
        <Icon className="h-4 w-4 text-zinc-400" />
      </div>
      <p data-testid={`${testId}-value`} className="mt-5 font-mono text-2xl font-semibold text-white">
        {value}
      </p>
      <p data-testid={`${testId}-detail`} className="mt-2 text-sm text-zinc-400">
        {detail}
      </p>
    </section>
  );
}

function RiskCard({ risk }) {
  const scoreWidth = Math.min(100, Math.max(6, risk.score));
  const asset = risk.asset || {};
  const vuln = risk.vulnerability || {};
  const service = risk.business_service || {};
  const threat = risk.matched_threat_intel;

  return (
    <article
      data-testid={`risk-card-${risk.risk_id}`}
      className="rounded-sm border border-zinc-800 bg-zinc-950 p-5 transition-colors duration-200 hover:border-zinc-700"
    >
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-3">
            <span data-testid={`risk-rank-${risk.risk_id}`} className="font-mono text-sm text-zinc-500">
              #{risk.rank.toString().padStart(2, "0")}
            </span>
            <span
              data-testid={`risk-severity-${risk.risk_id}`}
              className={`border px-2 py-1 font-mono text-xs uppercase tracking-[0.16em] ${statusColor[risk.severity]}`}
            >
              {risk.severity}
            </span>
            <span data-testid={`risk-cve-${risk.risk_id}`} className="font-mono text-sm text-zinc-300">
              {vuln.cve_id || "CVE pending"}
            </span>
          </div>
          <h2 data-testid={`risk-title-${risk.risk_id}`} className="mt-4 text-2xl font-semibold tracking-tight text-white">
            {asset.hostname || asset.asset_id} → {service.service || "Unknown service"}
          </h2>
          <p data-testid={`risk-explanation-${risk.risk_id}`} className="mt-3 max-w-4xl text-base leading-relaxed text-zinc-300">
            {risk.plain_english_explanation}
          </p>
        </div>
        <div className="w-full border border-zinc-800 bg-black p-4 lg:w-56">
          <p data-testid={`risk-score-label-${risk.risk_id}`} className="text-xs uppercase tracking-[0.2em] text-zinc-500">
            Risk Score
          </p>
          <p data-testid={`risk-score-${risk.risk_id}`} className="mt-2 font-mono text-3xl text-white">
            {risk.score.toFixed(1)}
          </p>
          <Progress data-testid={`risk-score-progress-${risk.risk_id}`} value={scoreWidth} className="mt-4 h-2 bg-zinc-800" />
        </div>
      </div>

      <div className="mt-5 grid gap-4 lg:grid-cols-3">
        <div data-testid={`risk-asset-evidence-${risk.risk_id}`} className="border border-zinc-800 bg-black p-4">
          <p className="mb-3 text-xs uppercase tracking-[0.2em] text-zinc-500">Asset Evidence</p>
          <dl className="space-y-2 text-sm">
            <div className="flex justify-between gap-4"><dt className="text-zinc-500">Exposure</dt><dd className="font-mono text-white">{asset.exposure}</dd></div>
            <div className="flex justify-between gap-4"><dt className="text-zinc-500">Environment</dt><dd className="font-mono text-white">{asset.environment}</dd></div>
            <div className="flex justify-between gap-4"><dt className="text-zinc-500">EDR</dt><dd className="font-mono text-white">{asset.edr_status}</dd></div>
          </dl>
        </div>
        <div data-testid={`risk-threat-evidence-${risk.risk_id}`} className="border border-zinc-800 bg-black p-4">
          <p className="mb-3 text-xs uppercase tracking-[0.2em] text-zinc-500">Threat Match</p>
          {threat ? (
            <div className="space-y-2 text-sm text-zinc-300">
              <p data-testid={`risk-threat-campaign-${risk.risk_id}`} className="text-white">{threat.campaign}</p>
              <p data-testid={`risk-threat-actor-${risk.risk_id}`} className="font-mono text-zinc-400">{threat.actor} · {threat.confidence}</p>
            </div>
          ) : (
            <p data-testid={`risk-threat-none-${risk.risk_id}`} className="text-sm text-zinc-500">No active campaign match in current data.</p>
          )}
        </div>
        <div data-testid={`risk-business-evidence-${risk.risk_id}`} className="border border-zinc-800 bg-black p-4">
          <p className="mb-3 text-xs uppercase tracking-[0.2em] text-zinc-500">Business Context</p>
          <p data-testid={`risk-business-owner-${risk.risk_id}`} className="text-sm text-white">{service.owner || asset.owner}</p>
          <p data-testid={`risk-business-scope-${risk.risk_id}`} className="mt-2 text-sm text-zinc-400">{service.compliance_scope || "Scope pending"}</p>
        </div>
      </div>

      {risk.kev_evidence && (
        <div data-testid={`risk-kev-evidence-${risk.risk_id}`} className="mt-5 border border-red-900/70 bg-red-950/30 p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="text-xs uppercase tracking-[0.2em] text-red-300">CISA KEV Evidence</p>
            <a
              data-testid={`risk-kev-source-${risk.risk_id}`}
              href={risk.kev_evidence.source_url}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 font-mono text-xs text-red-200 underline-offset-4 hover:underline"
            >
              live catalog <ExternalLink className="h-3 w-3" />
            </a>
          </div>
          <dl className="mt-3 grid gap-2 text-sm md:grid-cols-3">
            <div className="flex justify-between gap-3"><dt className="text-red-300">Date Added</dt><dd className="font-mono text-white">{risk.kev_evidence.date_added || "—"}</dd></div>
            <div className="flex justify-between gap-3"><dt className="text-red-300">Ransomware Use</dt><dd className="font-mono text-white">{risk.kev_evidence.known_ransomware_campaign_use ? "yes" : "no"}</dd></div>
            <div className="flex justify-between gap-3"><dt className="text-red-300">Required Action</dt><dd className="line-clamp-2 text-zinc-300">{risk.kev_evidence.required_action || "—"}</dd></div>
          </dl>
        </div>
      )}

      <div className="mt-5 grid gap-4 lg:grid-cols-[0.9fr_1.1fr]">
        <div data-testid={`risk-scoring-factors-${risk.risk_id}`} className="border border-zinc-800 bg-zinc-900 p-4">
          <p className="mb-3 text-xs uppercase tracking-[0.2em] text-zinc-500">Why It Ranked Here</p>
          <ul className="space-y-2 text-sm text-zinc-300">
            {(risk.scoring_factors || []).map((factor, index) => (
              <li data-testid={`risk-factor-${risk.risk_id}-${index}`} key={factor} className="flex gap-2">
                <span className="font-mono text-zinc-600">{String(index + 1).padStart(2, "0")}</span>
                <span>{factor}</span>
              </li>
            ))}
          </ul>
        </div>
        <div data-testid={`risk-remediation-${risk.risk_id}`} className="border border-zinc-800 bg-zinc-900 p-4">
          <p className="mb-3 text-xs uppercase tracking-[0.2em] text-zinc-500">NIST 800-53 Guidance</p>
          {risk.remediation_hint && (
            <div data-testid={`risk-remediation-hint-${risk.risk_id}`} className="mb-3 border-l-2 border-zinc-600 bg-black/40 px-3 py-2">
              <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-zinc-500">Internal Hint (not the answer)</p>
              <p className="mt-1 text-sm text-zinc-300">{risk.remediation_hint}</p>
            </div>
          )}
          {risk.nist_sync_required ? (
            <p data-testid={`risk-nist-sync-required-${risk.risk_id}`} className="text-sm text-yellow-300">
              Official NIST controls are not synced yet. Use “Sync NIST Controls” to retrieve the live NIST CSV source.
            </p>
          ) : (
            <div className="space-y-3">
              {(risk.remediation_guidance || []).map((control) => (
                <div data-testid={`risk-guidance-${risk.risk_id}-${control.identifier}`} key={control.identifier} className="border-l border-zinc-700 pl-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <p className="font-mono text-sm text-white">{control.identifier} · {control.name}</p>
                    {control.source_url && (
                      <a
                        data-testid={`risk-guidance-source-${risk.risk_id}-${control.identifier}`}
                        href={control.source_url}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1 font-mono text-[10px] uppercase tracking-[0.16em] text-zinc-500 hover:text-zinc-200"
                      >
                        NIST CSRC <ExternalLink className="h-3 w-3" />
                      </a>
                    )}
                  </div>
                  <p className="mt-1 line-clamp-3 text-sm text-zinc-400">{control.control_text || control.discussion}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </article>
  );
}

function App() {
  const [health, setHealth] = useState(null);
  const [riskResponse, setRiskResponse] = useState(null);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [syncingKev, setSyncingKev] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [reportOpen, setReportOpen] = useState(false);

  const risks = riskResponse?.risks || [];
  const topRisk = risks[0];
  const nist = riskResponse?.nist_status || health?.nist_status || {};
  const qdrant = riskResponse?.qdrant_status || health?.qdrant_status || {};
  const kev = riskResponse?.kev_status || health?.kev_status || {};
  const threatReport = riskResponse?.threat_report;

  const criticalCount = risks.filter((risk) => risk.severity === "critical").length;

  const loadDashboard = async () => {
    setLoading(true);
    setError("");
    try {
      const [healthRes, risksRes] = await Promise.all([
        axios.get(`${API}/health`),
        axios.get(`${API}/risks/top?limit=5`),
      ]);
      setHealth(healthRes.data);
      setRiskResponse(risksRes.data);
    } catch (err) {
      setError(err.response?.data?.detail || err.message || "Unable to load dashboard");
    } finally {
      setLoading(false);
    }
  };

  const syncNist = async () => {
    setSyncing(true);
    setMessage("");
    setError("");
    try {
      const response = await axios.post(`${API}/nist/sync`);
      setMessage(`Synced ${response.data.controls_loaded} official NIST controls from CSRC.`);
      await loadDashboard();
    } catch (err) {
      setError(err.response?.data?.detail || err.message || "NIST sync failed");
    } finally {
      setSyncing(false);
    }
  };

  const syncKev = async () => {
    setSyncingKev(true);
    setMessage("");
    setError("");
    try {
      const response = await axios.post(`${API}/cisa-kev/sync`);
      setMessage(`Synced ${response.data.entries_loaded} CISA KEV entries from the live catalog.`);
      await loadDashboard();
    } catch (err) {
      setError(err.response?.data?.detail || err.message || "CISA KEV sync failed");
    } finally {
      setSyncingKev(false);
    }
  };



  const uploadDataPack = async (event) => {
    const selected = Array.from(event.target.files || []);
    if (!selected.length) return;
    const formData = new FormData();
    selected.forEach((file) => formData.append("files", file));
    setUploading(true);
    setMessage("");
    setError("");
    try {
      const response = await axios.post(`${API}/data/upload`, formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      setMessage(`Uploaded data pack: ${Object.keys(response.data.loaded).join(", ")}.`);
      await loadDashboard();
    } catch (err) {
      setError(err.response?.data?.detail || err.message || "Upload failed");
    } finally {
      setUploading(false);
      event.target.value = "";
    }
  };

  useEffect(() => {
    loadDashboard();
  }, []);

  return (
    <main data-testid="cyber-risk-dashboard" className="min-h-screen bg-zinc-950 text-zinc-100">
      <header data-testid="dashboard-header" className="sticky top-0 z-50 border-b border-zinc-800 bg-zinc-950/95 backdrop-blur">
        <div className="mx-auto flex max-w-7xl flex-col gap-4 px-5 py-4 md:flex-row md:items-center md:justify-between md:px-8">
          <div>
            <p data-testid="dashboard-eyebrow" className="text-xs uppercase tracking-[0.28em] text-zinc-500">
              TawasolPay · Board Risk Briefing
            </p>
            <h1 data-testid="dashboard-title" className="mt-2 text-3xl font-bold tracking-tight text-white md:text-4xl">
              AI Cyber Risk Assistant
            </h1>
          </div>
          <nav data-testid="dashboard-actions" className="flex flex-wrap gap-2">
            <Button data-testid="refresh-dashboard-button" onClick={loadDashboard} className="rounded-sm border border-zinc-700 bg-zinc-900 text-white hover:bg-zinc-800">
              <RefreshCw className="mr-2 h-4 w-4" /> Refresh
            </Button>
            <Button data-testid="sync-cisa-kev-button" onClick={syncKev} disabled={syncingKev} className="rounded-sm border border-red-700/70 bg-red-950/70 text-red-100 hover:bg-red-900">
              <Siren className="mr-2 h-4 w-4" /> {syncingKev ? "Syncing..." : "Sync CISA KEV"}
            </Button>
            <Button data-testid="sync-nist-controls-button" onClick={syncNist} disabled={syncing} className="rounded-sm bg-white text-black hover:bg-zinc-200">
              <Database className="mr-2 h-4 w-4" /> {syncing ? "Syncing..." : "Sync NIST Controls"}
            </Button>
          </nav>
        </div>
      </header>

      <section className="mx-auto max-w-7xl px-5 py-8 md:px-8">
        <div data-testid="hero-panel" className="grid gap-6 lg:grid-cols-[1.15fr_0.85fr]">
          <div className="border border-zinc-800 bg-zinc-900 p-6 md:p-8">
            <div className="flex items-center gap-3 text-zinc-400">
              <ShieldAlert className="h-5 w-5 text-red-400" />
              <span data-testid="hero-status-text" className="font-mono text-sm uppercase tracking-[0.18em]">
                48-hour MDR advisory response mode
              </span>
            </div>
            <h2 data-testid="hero-heading" className="mt-6 max-w-4xl text-4xl font-bold leading-none tracking-tight text-white md:text-6xl">
              Rank exposure by exploitability, threat match, and business blast radius.
            </h2>
            <p data-testid="hero-description" className="mt-5 max-w-3xl text-base leading-relaxed text-zinc-400 md:text-lg">
              This working prototype combines deterministic scoring, official NIST 800-53 retrieval, and Qdrant-ready vector search placeholders.
            </p>
          </div>
          <aside data-testid="operations-console" className="border border-zinc-800 bg-black p-5 font-mono text-sm text-zinc-400">
            <div className="mb-4 flex items-center gap-2 text-white">
              <TerminalSquare className="h-4 w-4" />
              <span data-testid="console-title">SYSTEM CONSOLE</span>
            </div>
            <p data-testid="console-api-status">api.status = {loading ? "loading" : error ? "attention" : "healthy"}</p>
            <p data-testid="console-dataset-mode">dataset.mode = {riskResponse?.dataset_mode || health?.dataset_mode || "pending"}</p>
            <p data-testid="console-nist-status">nist.controls = {nist.controls_loaded || 0}</p>
            <p data-testid="console-kev-status">kev.entries = {kev.entries_loaded || 0}</p>
            <p data-testid="console-qdrant-mode">qdrant.mode = {qdrant.mode || "pending"}</p>
            <p data-testid="console-llm-mode">llm.wording = {health?.llm_wording || "deterministic-template"}</p>
          </aside>
        </div>

        {(message || error) && (
          <div
            data-testid={error ? "dashboard-error-message" : "dashboard-success-message"}
            className={`mt-6 border p-4 text-sm ${error ? "border-red-500 bg-red-950/40 text-red-200" : "border-green-600 bg-green-950/30 text-green-200"}`}
          >
            {error || message}
          </div>
        )}

        <section data-testid="metrics-grid" className="mt-6 grid gap-4 md:grid-cols-2 xl:grid-cols-5">
          <MetricCard testId="metric-top-risk" icon={AlertTriangle} label="Top Risk" value={topRisk ? topRisk.vulnerability?.cve_id : "—"} detail={topRisk ? topRisk.asset?.hostname : "Awaiting analysis"} />
          <MetricCard testId="metric-critical-risks" icon={Activity} label="Critical Risks" value={criticalCount} detail="Based on hybrid scoring threshold" />
          <MetricCard testId="metric-nist-controls" icon={Database} label="NIST Controls" value={nist.controls_loaded || 0} detail={nist.synced ? "Official CSRC source synced" : "Click sync to retrieve"} />
          <MetricCard testId="metric-kev-entries" icon={Siren} label="CISA KEV" value={kev.entries_loaded || 0} detail={kev.synced ? "Live catalog synced" : "Click sync to retrieve"} />
          <MetricCard testId="metric-vector-mode" icon={Server} label="Vector Store" value={qdrant.configured ? "Qdrant" : "Fallback"} detail={qdrant.configured ? "Env credentials detected" : "Qdrant placeholders active"} />
        </section>

        {threatReport && (
          <section data-testid="mdr-advisory-panel" className="mt-6 border border-amber-700/70 bg-amber-950/20 p-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <FileText className="h-5 w-5 text-amber-300" />
                <p data-testid="mdr-advisory-title" className="font-mono text-sm uppercase tracking-[0.2em] text-amber-200">
                  MDR Advisory · {threatReport.filename}
                </p>
              </div>
              <Button
                data-testid="mdr-advisory-toggle"
                onClick={() => setReportOpen((open) => !open)}
                className="rounded-sm border border-amber-700/70 bg-transparent text-amber-100 hover:bg-amber-900/40"
              >
                {reportOpen ? "Collapse" : "Read advisory"}
              </Button>
            </div>
            {reportOpen && (
              <pre data-testid="mdr-advisory-content" className="mt-4 max-h-96 overflow-y-auto whitespace-pre-wrap border border-amber-900/40 bg-black/40 p-4 font-mono text-xs leading-relaxed text-amber-100">
                {threatReport.content}
              </pre>
            )}
          </section>
        )}

        <section data-testid="data-ingestion-panel" className="mt-6 grid gap-4 border border-zinc-800 bg-zinc-900 p-5 lg:grid-cols-[1fr_auto_auto] lg:items-center">
          <div>
            <p data-testid="data-ingestion-title" className="text-xs uppercase tracking-[0.2em] text-zinc-500">Data Pack</p>
            <p data-testid="data-ingestion-description" className="mt-2 text-sm text-zinc-300">
              Upload the six assignment files when ready.
            </p>
          </div>
          <label data-testid="upload-data-pack-label" className="inline-flex cursor-pointer items-center justify-center rounded-sm border border-zinc-700 bg-zinc-950 px-4 py-2 text-sm text-white transition-colors duration-200 hover:bg-zinc-800">
            <FileUp className="mr-2 h-4 w-4" /> {uploading ? "Uploading..." : "Upload Data Pack"}
            <input data-testid="upload-data-pack-input" type="file" multiple accept=".csv,.md" onChange={uploadDataPack} className="hidden" />
          </label>

        </section>

        <section data-testid="risk-list-section" className="mt-8">
          <div className="mb-4 flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
            <div>
              <p data-testid="risk-list-eyebrow" className="text-xs uppercase tracking-[0.2em] text-zinc-500">Prioritized Output</p>
              <h2 data-testid="risk-list-title" className="mt-2 text-2xl font-semibold tracking-tight text-white">Top 5 Explainable Cyber Risks</h2>
            </div>
            <p data-testid="risk-generated-at" className="font-mono text-xs text-zinc-500">
              generated_at = {riskResponse?.generated_at || "pending"}
            </p>
          </div>

          {loading ? (
            <div data-testid="risk-list-loading" className="border border-zinc-800 bg-zinc-900 p-10 text-center text-zinc-400">
              Loading risk model...
            </div>
          ) : (
            <div className="space-y-4">
              {risks.map((risk) => (
                <RiskCard key={risk.risk_id} risk={risk} />
              ))}
            </div>
          )}
        </section>
      </section>
    </main>
  );
}

export default App;