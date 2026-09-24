import { useState } from "react";
import { Badge, Card, EvidenceTypeBadge, Mono, SeverityBadge } from "./ui.jsx";

const ORDER = ["critical", "high", "medium", "low", "info"];

export default function Findings({ findings }) {
  const [filter, setFilter] = useState("all");
  const sorted = [...findings].sort((a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity));
  const shown = filter === "all" ? sorted : sorted.filter((f) => f.severity === filter);
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <span className="text-slate-500">Filter:</span>
        {["all", ...ORDER].map((s) => (
          <button key={s} onClick={() => setFilter(s)}
            className={`rounded-md px-2 py-0.5 ${filter === s ? "bg-sky-500/20 text-sky-200" : "text-slate-400 hover:text-slate-200"}`}>
            {s} ({s === "all" ? findings.length : findings.filter((f) => f.severity === s).length})
          </button>
        ))}
      </div>
      {shown.map((f) => (
        <Card key={f.finding_id}>
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={f.severity} />
            <Badge tone="violet">confidence {f.confidence}</Badge>
            <EvidenceTypeBadge type={f.finding_type} />
            <Badge>{f.category}</Badge>
            <span className="ml-auto font-mono text-[11px] text-slate-600">{f.finding_id}</span>
          </div>
          <h3 className="mt-2 font-semibold text-slate-100">{f.title}</h3>
          <p className="mt-1 text-sm text-slate-300">{f.description}</p>
          {f.why_it_matters && <p className="mt-1 text-sm text-slate-400"><span className="text-slate-500">Why it matters: </span>{f.why_it_matters}</p>}
          {f.evidence.length > 0 && (
            <div className="mt-2 rounded-lg bg-slate-950/70 p-2">
              <div className="mb-1 text-xs font-semibold uppercase text-slate-500">Evidence</div>
              <ul className="space-y-1 text-xs">
                {f.evidence.map((e, i) => (
                  <li key={i} className="break-all"><EvidenceTypeBadge type={e.type} /> <span className="text-slate-400">{e.label}:</span>{" "}
                    <span className="text-slate-200">{typeof e.value === "object" ? JSON.stringify(e.value) : String(e.value)}</span>
                    {e.source && <span className="text-slate-600"> · {e.source}</span>}</li>
                ))}
              </ul>
            </div>
          )}
          <div className="mt-2 flex flex-wrap gap-3 text-xs text-slate-500">
            {f.sources.length > 0 && <span>Sources: {f.sources.join(", ")}</span>}
            {f.related_indicators.length > 0 && <span>Related: {f.related_indicators.map((r) => <Mono key={r}>{r} </Mono>)}</span>}
          </div>
        </Card>
      ))}
    </div>
  );
}
