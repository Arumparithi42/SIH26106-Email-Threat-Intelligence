import { Badge, Card, Empty, Mono, ProviderResult, SeverityBadge } from "./ui.jsx";

export default function UrlAnalysis({ report }) {
  const urls = report.url_analysis;
  if (!urls.length) return <Empty>No URLs found in the email.</Empty>;
  return (
    <div className="flex flex-col gap-4">
      <p className="text-xs text-slate-500">Passive analysis only: none of these links were visited, downloaded or rendered.</p>
      {urls.map((u) => (
        <Card key={u.url} title={<span className="break-all font-mono text-[13px] normal-case text-sky-200">{u.url}</span>}>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-1 text-sm">
              <div><span className="text-slate-500">Scheme</span> {u.scheme} · <span className="text-slate-500">Host</span> <Mono>{u.hostname}</Mono>{u.port ? `:${u.port}` : ""}</div>
              <div><span className="text-slate-500">Registrable domain</span> <Mono>{u.domain || (u.is_ip_based ? "(IP address)" : "—")}</Mono></div>
              <div className="break-all"><span className="text-slate-500">Path</span> <Mono>{u.path || "/"}</Mono>{u.query && <> <span className="text-slate-500">Query</span> <Mono>{u.query}</Mono></>}</div>
              <div><span className="text-slate-500">Found in</span> {u.found_in.join(", ")}</div>
              {u.display_texts?.length > 0 && <div><span className="text-slate-500">Visible link text</span> "{u.display_texts.join('", "')}"</div>}
              {u.resolved_ips?.length > 0 && <div><span className="text-slate-500">Resolves to</span> <Mono>{u.resolved_ips.join(", ")}</Mono></div>}
              <div className="flex flex-wrap gap-1 pt-1">
                {u.is_ip_based && <Badge tone="orange">IP-BASED URL</Badge>}
                {u.lookalike_of && <Badge tone="red" icon="≈">imitates {u.lookalike_of}</Badge>}
              </div>
            </div>
            <div>
              <h4 className="mb-1 text-xs font-semibold uppercase text-slate-400">Suspicious characteristics</h4>
              {u.characteristics.length ? (
                <ul className="space-y-1">
                  {u.characteristics.map((c) => (
                    <li key={c.code} className="flex items-start gap-2 text-sm"><SeverityBadge severity={c.severity} /><span className="text-slate-300">{c.description}</span></li>
                  ))}
                </ul>
              ) : <p className="text-sm text-slate-500">None detected.</p>}
              <h4 className="mb-1 mt-3 text-xs font-semibold uppercase text-slate-400">Threat intelligence</h4>
              <table className="w-full text-sm">
                <tbody>
                  {Object.entries(u.reputation || {}).map(([k, r]) => (
                    <tr key={k} className="border-t border-slate-800"><td className="py-1 text-slate-400">{k}</td><td><ProviderResult result={r} /></td>
                      <td className="text-xs text-slate-500">{r.summary}</td></tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </Card>
      ))}
    </div>
  );
}
