import { Badge, Card } from "./ui.jsx";

function Events({ events }) {
  return (
    <ol className="relative ml-3 border-l border-slate-700">
      {events.map((e, i) => (
        <li key={i} className="mb-3 ml-5">
          <span className={`absolute -left-[7px] h-3 w-3 rounded-full ring-4 ring-slate-950 ${e.status === "error" ? "bg-amber-500" : e.kind === "email" ? "bg-violet-400" : "bg-emerald-400"}`} />
          <div className="flex flex-wrap items-baseline gap-2">
            <span className="font-mono text-xs text-slate-500">{e.timestamp ? new Date(e.timestamp).toISOString().replace("T", " ").slice(0, 23) : "—"}</span>
            <span className="text-sm text-slate-200">{e.event}</span>
            <Badge tone={e.status === "error" ? "amber" : e.status === "observed" ? "violet" : "green"}>{e.status.toUpperCase()}</Badge>
          </div>
          {e.detail && <div className="text-xs text-slate-500">{e.detail}</div>}
        </li>
      ))}
    </ol>
  );
}

export default function Timeline({ report }) {
  const email = report.timeline.filter((e) => e.kind === "email");
  const inv = report.timeline.filter((e) => e.kind === "investigation");
  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <Card title="Email timeline" subtitle="Reconstructed from the Date header (set by the sender) and Received headers (UTC).">
        {email.length ? <Events events={email} /> : <p className="text-sm text-slate-500">No timestamps in headers.</p>}
      </Card>
      <Card title="Investigation timeline" subtitle="Each analysis stage with the time it completed (UTC).">
        <Events events={inv} />
      </Card>
    </div>
  );
}
