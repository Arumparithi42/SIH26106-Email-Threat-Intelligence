import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Badge, Card, ConfidenceBadge, RiskBadge, SeverityBadge, StatusBadge } from "./ui.jsx";

const SEV_COLOR = { critical: "#be123c", high: "#ef4444", medium: "#f97316", low: "#eab308", info: "#38bdf8" };

function Stat({ label, value, onClick }) {
  return (
    <button onClick={onClick} className="rounded-lg border border-slate-800 bg-slate-950/50 p-3 text-left hover:border-slate-600">
      <div className="text-2xl font-semibold text-slate-100">{value}</div>
      <div className="text-xs uppercase tracking-wide text-slate-500">{label}</div>
    </button>
  );
}

export default function ExecutiveSummary({ report, onNavigate }) {
  const risk = report.risk_assessment;
  const auth = report.header_forensics.authentication;
  const td = report.threat_detection;
  const ind = report.indicators;
  const data = risk.contributions.slice(0, 10).map((c) => ({ name: c.title.length > 38 ? c.title.slice(0, 36) + "…" : c.title, points: c.points, severity: c.severity, dimension: c.dimension }));
  const top = [...report.findings].sort((a, b) => ["critical", "high", "medium", "low", "info"].indexOf(a.severity) - ["critical", "high", "medium", "low", "info"].indexOf(b.severity)).slice(0, 6);

  return (
    <div className="grid gap-5 lg:grid-cols-3">
      <Card title="Risk assessment" className="lg:col-span-1">
        <div className="flex items-center gap-3">
          <RiskBadge level={risk.risk_level} big />
          <div className="text-3xl font-bold text-slate-100">{risk.risk_score}<span className="text-base text-slate-500">/100</span></div>
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          <ConfidenceBadge level={risk.confidence} />
          <Badge tone="violet">THREAT TYPE: {risk.classification.toUpperCase()}</Badge>
        </div>
        <div className="mt-3 text-xs text-slate-400">
          Evidence dimensions: {risk.evidence_dimensions.join(", ") || "none"}
        </div>
        {risk.caps_applied.length > 0 && (
          <div className="mt-2 rounded-md bg-amber-500/10 p-2 text-xs text-amber-300">Cap applied: {risk.caps_applied.join("; ")}</div>
        )}
        <h4 className="mt-4 text-xs font-semibold uppercase text-slate-400">Why this classification</h4>
        <ul className="mt-1 list-disc space-y-0.5 pl-4 text-xs text-slate-400">
          {risk.classification_rationale.map((r) => <li key={r}>{r}</li>)}
        </ul>
        <h4 className="mt-4 text-xs font-semibold uppercase text-slate-400">Confidence factors</h4>
        <ul className="mt-1 list-disc space-y-0.5 pl-4 text-xs text-slate-400">
          {risk.confidence_factors.map((r) => <li key={r}>{r}</li>)}
        </ul>
      </Card>

      <Card title="What drives the score" subtitle="Each bar is one finding: severity points × confidence factor. No hidden inputs." className="lg:col-span-2">
        {data.length ? (
          <ResponsiveContainer width="100%" height={Math.max(160, data.length * 30)}>
            <BarChart data={data} layout="vertical" margin={{ left: 10, right: 20 }}>
              <CartesianGrid horizontal={false} stroke="#1e293b" />
              <XAxis type="number" stroke="#64748b" fontSize={11} />
              <YAxis type="category" dataKey="name" width={230} stroke="#64748b" fontSize={11} />
              <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155", fontSize: 12 }}
                formatter={(v, _n, p) => [`${v} pts (${p.payload.severity}, ${p.payload.dimension})`, "contribution"]} />
              <Bar dataKey="points" radius={[0, 4, 4, 0]}>
                {data.map((d) => <Cell key={d.name} fill={SEV_COLOR[d.severity]} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        ) : <p className="text-sm text-slate-400">No risk-increasing findings.</p>}
        <p className="mt-2 text-xs text-slate-500">{risk.method}</p>
      </Card>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-5 lg:col-span-3">
        <Stat label="Findings" value={report.findings.length} onClick={() => onNavigate("findings")} />
        <Stat label="IP addresses" value={ind.ips.length} onClick={() => onNavigate("ips")} />
        <Stat label="Domains" value={ind.domains.length} onClick={() => onNavigate("domains")} />
        <Stat label="URLs" value={ind.urls.length} onClick={() => onNavigate("urls")} />
        <Stat label="Attachments" value={ind.attachments.length} onClick={() => onNavigate("email")} />
      </div>

      <Card title="Authentication" right={<button onClick={() => onNavigate("auth")} className="text-xs text-sky-400">details →</button>}>
        <div className="space-y-2">
          {["spf", "dkim", "dmarc"].map((m) => (
            <div key={m} className="flex items-center justify-between">
              <span className="font-mono text-sm uppercase text-slate-300">{m}</span>
              <span className="flex items-center gap-2">
                <StatusBadge status={auth[m].status} />
                <span className="text-[11px] text-slate-500">{auth[m].status_source === "receiver_reported" ? "receiver-reported" : "independent check"}</span>
              </span>
            </div>
          ))}
        </div>
      </Card>

      <Card title="Threat detection">
        <div className="space-y-2 text-sm">
          <div className="flex justify-between"><span className="text-slate-400">ML classifier</span>
            <span>{td.ml?.predicted_category ?? "—"} <span className="text-slate-500">p={td.ml?.probability ?? "—"}</span></span></div>
          <div className="flex justify-between"><span className="text-slate-400">Rule category</span><span>{td.rule_category || "none"}</span></div>
          <div className="flex justify-between"><span className="text-slate-400">Rule matches</span><span>{td.rule_matches.length}</span></div>
          <div className="flex flex-wrap gap-1 pt-1">{td.matched_groups.map((g) => <Badge key={g} tone="orange">{g.replaceAll("_", " ")}</Badge>)}</div>
        </div>
      </Card>

      <Card title="Top findings" right={<button onClick={() => onNavigate("findings")} className="text-xs text-sky-400">all →</button>}>
        <ul className="space-y-2">
          {top.map((f) => (
            <li key={f.finding_id} className="flex items-start gap-2 text-sm">
              <SeverityBadge severity={f.severity} />
              <span className="text-slate-300">{f.title}</span>
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}
