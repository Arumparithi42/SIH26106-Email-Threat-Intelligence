import { Badge, Card, Empty, KV, Mono, SeverityBadge } from "./ui.jsx";

function fmtDelta(s) {
  if (s === null || s === undefined) return null;
  const abs = Math.abs(s);
  const t = abs < 120 ? `${abs}s` : abs < 7200 ? `${Math.round(abs / 60)} min` : `${(abs / 3600).toFixed(1)} h`;
  return s < 0 ? `−${t}` : `+${t}`;
}

export default function HeaderForensics({ report }) {
  const hf = report.header_forensics;
  const h = report.email.headers;
  const labels = { reply_to: "Reply-To", return_path: "Return-Path", message_id: "Message-ID", sender: "Sender", dkim_d: "DKIM d=" };
  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <Card title="Sender identity" subtitle="Domains that should normally belong to the same organisation as the From domain.">
        <div className="mb-3 text-sm">From domain: <Mono>{hf.identity.domains.from || "—"}</Mono></div>
        <table className="w-full text-sm">
          <thead><tr className="text-left text-xs text-slate-500"><th className="pb-1">Header</th><th>Domain</th><th>Relationship to From</th></tr></thead>
          <tbody>
            {hf.identity.comparisons.map((c) => (
              <tr key={c.field} className="border-t border-slate-800">
                <td className="py-1.5 text-slate-400">{labels[c.field] || c.field}</td>
                <td><Mono>{c.domain}</Mono></td>
                <td>{c.aligned_with_from ? <Badge tone="green" icon="=">SAME ORGANISATION</Badge> : <Badge tone="orange" icon="≠">MISMATCH</Badge>}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {hf.identity.comparisons.some((c) => !c.aligned_with_from) && (
          <p className="mt-3 text-xs text-slate-400">
            A mismatch means replies, bounces or the message origin point to a different organisation than the visible sender.
            Some legitimate services (newsletters, ticketing systems) do this too, so it is evidence and is weighed with other findings.
          </p>
        )}
      </Card>

      <Card title="Important headers">
        <KV rows={[
          ["Date", h.date], ["Message-ID", h.message_id && <Mono key="m">{h.message_id}</Mono>], ["X-Mailer", h.x_mailer], ["User-Agent", h.user_agent],
          ["X-Originating-IP", h.x_originating_ip], ["Sending IP (for SPF)", hf.sending_ip.ip && <span key="s"><Mono>{hf.sending_ip.ip}</Mono> <span className="text-xs text-slate-500">{hf.sending_ip.method}</span></span>],
        ]} />
      </Card>

      <Card title="Received chain: route reconstruction" subtitle="Oldest hop first. Only the last hop (added by the recipient's own server) is fully trustworthy; earlier hops can be forged by the sender." className="lg:col-span-2">
        {hf.received_chain.length ? (
          <ol className="relative ml-3 border-l border-slate-700">
            {hf.received_chain.map((hop) => (
              <li key={hop.hop} className="mb-4 ml-5">
                <span className={`absolute -left-[9px] flex h-4 w-4 items-center justify-center rounded-full ring-4 ring-slate-950 ${hop.ip_is_public ? "bg-sky-500" : "bg-slate-600"}`} />
                <div className="flex flex-wrap items-baseline gap-2">
                  <span className="text-sm font-semibold text-slate-200">Hop {hop.hop}</span>
                  <span className="text-xs text-slate-500">{hop.timestamp ? new Date(hop.timestamp).toUTCString() : "no timestamp"}</span>
                  {fmtDelta(hop.time_delta_seconds) && <Badge tone={hop.time_delta_seconds < 0 || hop.time_delta_seconds > 3600 ? "amber" : "slate"}>{fmtDelta(hop.time_delta_seconds)}</Badge>}
                  <Badge tone={hop.trust === "recorded_by_final_receiver" ? "green" : "slate"}>{hop.trust === "recorded_by_final_receiver" ? "recorded by final receiver" : "upstream claim"}</Badge>
                </div>
                <div className="mt-1 text-sm text-slate-300">
                  <span className="text-slate-500">from</span> {hop.hostname || "unknown"} {hop.ip && <Mono>[{hop.ip}]</Mono>} {hop.ip && !hop.ip_is_public && <Badge>private</Badge>}
                  <span className="text-slate-500"> → by</span> {hop.server || "unknown"} {hop.protocol && <span className="text-xs text-slate-500">({hop.protocol})</span>}
                </div>
                <details className="mt-1 text-xs text-slate-500"><summary className="cursor-pointer">raw header</summary><Mono>{hop.raw}</Mono></details>
              </li>
            ))}
          </ol>
        ) : <Empty>No Received headers.</Empty>}
      </Card>

      <Card title="Routing & header anomalies" subtitle="Anomalies requiring investigation, not verdicts." className="lg:col-span-2">
        {hf.anomalies.length ? (
          <ul className="space-y-2">
            {hf.anomalies.map((a, i) => (
              <li key={i} className="flex items-start gap-2 text-sm">
                <SeverityBadge severity={a.severity} />
                <div><div className="text-slate-200">{a.description}</div><div className="text-xs text-slate-500">{a.interpretation}</div></div>
              </li>
            ))}
          </ul>
        ) : <Empty>No routing anomalies detected.</Empty>}
      </Card>
    </div>
  );
}
