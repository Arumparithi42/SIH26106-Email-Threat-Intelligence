import { useEffect, useState } from "react";
import { api } from "../services/api.js";
import { Badge, ConfidenceBadge, Empty, RiskBadge } from "../components/ui.jsx";
import ExecutiveSummary from "../components/ExecutiveSummary.jsx";
import EmailDetails from "../components/EmailDetails.jsx";
import AuthenticationPanel from "../components/AuthenticationPanel.jsx";
import HeaderForensics from "../components/HeaderForensics.jsx";
import IpIntelligence from "../components/IpIntelligence.jsx";
import DomainIntelligence from "../components/DomainIntelligence.jsx";
import UrlAnalysis from "../components/UrlAnalysis.jsx";
import ThreatGraph from "../components/ThreatGraph.jsx";
import Timeline from "../components/Timeline.jsx";
import Findings from "../components/Findings.jsx";

const TABS = [
  ["summary", "Executive summary"], ["email", "Email details"], ["auth", "Authentication"], ["headers", "Header forensics"],
  ["ips", "IP intelligence"], ["domains", "Domain intelligence"], ["urls", "URL analysis"], ["graph", "Threat graph"],
  ["timeline", "Timeline"], ["findings", "Findings"],
];

export default function AnalysisPage({ id }) {
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);
  const [tab, setTab] = useState("summary");

  useEffect(() => {
    setReport(null);
    setError(null);
    api.analysis(id).then(setReport).catch((e) => setError(e.message));
  }, [id]);

  if (error) return <Empty>Could not load analysis {id}: {error}</Empty>;
  if (!report) return <Empty>Loading analysis {id}…</Empty>;

  const risk = report.risk_assessment;
  const h = report.email.headers;
  const counts = {
    findings: report.findings.length,
    ips: report.ip_intelligence.length,
    domains: report.domain_intelligence.length,
    urls: report.url_analysis.length,
  };
  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-slate-800 bg-slate-900/60 p-4">
        <div className="min-w-0">
          <div className="text-xs text-slate-500">Analysis {report.analysis_id} · {new Date(report.created_at).toLocaleString()} · {report.input.filename || "raw input"}</div>
          <h1 className="mt-1 truncate text-lg font-semibold text-slate-100">{h.subject || "(no subject)"}</h1>
          <div className="truncate text-sm text-slate-400">From {h.from?.raw || "—"}</div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <RiskBadge level={risk.risk_level} big />
          <ConfidenceBadge level={risk.confidence} />
          <Badge tone="violet">{risk.classification.toUpperCase()}</Badge>
          <a href={api.reportUrl(report.analysis_id)} target="_blank" rel="noreferrer"
            className="rounded-lg bg-sky-600 px-3 py-1.5 text-sm font-semibold text-white hover:bg-sky-500">
            ⤓ Generate Forensic Report (PDF)
          </a>
        </div>
      </div>

      <nav className="flex flex-wrap gap-1 border-b border-slate-800">
        {TABS.map(([key, label]) => (
          <button key={key} onClick={() => setTab(key)}
            className={`-mb-px border-b-2 px-3 py-2 text-sm ${tab === key ? "border-sky-400 text-sky-200" : "border-transparent text-slate-400 hover:text-slate-200"}`}>
            {label}
            {counts[key] !== undefined && <span className="ml-1.5 rounded bg-slate-800 px-1.5 text-xs text-slate-400">{counts[key]}</span>}
          </button>
        ))}
      </nav>

      {tab === "summary" && <ExecutiveSummary report={report} onNavigate={setTab} />}
      {tab === "email" && <EmailDetails report={report} />}
      {tab === "auth" && <AuthenticationPanel report={report} />}
      {tab === "headers" && <HeaderForensics report={report} />}
      {tab === "ips" && <IpIntelligence report={report} />}
      {tab === "domains" && <DomainIntelligence report={report} />}
      {tab === "urls" && <UrlAnalysis report={report} />}
      {tab === "graph" && <ThreatGraph report={report} />}
      {tab === "timeline" && <Timeline report={report} />}
      {tab === "findings" && <Findings findings={report.findings} />}
    </div>
  );
}
