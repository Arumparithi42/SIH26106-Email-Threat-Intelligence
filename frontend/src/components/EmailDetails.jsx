import { useState } from "react";
import { Badge, Card, Empty, KV, Mono, SeverityBadge } from "./ui.jsx";

const addr = (a) => (a ? (a.display_name ? `${a.display_name} <${a.address}>` : a.address) : null);

export default function EmailDetails({ report }) {
  const e = report.email;
  const h = e.headers;
  const [showHtml, setShowHtml] = useState(false);
  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <Card title="Envelope & headers">
        <KV rows={[
          ["From", addr(h.from)], ["To", h.to.map(addr).join(", ")], ["Cc", h.cc.map(addr).join(", ") || null],
          ["Subject", h.subject], ["Date", h.date], ["Reply-To", addr(h.reply_to)], ["Return-Path", addr(h.return_path)],
          ["Message-ID", h.message_id && <Mono>{h.message_id}</Mono>], ["MIME", `${e.mime.content_type} (${e.mime.parts.length} part(s))`],
          ["X-Mailer / UA", h.x_mailer || h.user_agent], ["SHA-256", <Mono key="s">{report.input.sha256}</Mono>], ["Size", `${report.input.size_bytes} bytes`],
        ]} />
      </Card>

      <Card title={`Attachments (${e.attachments.length})`} subtitle="Static metadata only. Attachments were never opened, saved or executed.">
        {e.attachments.length ? (
          <ul className="space-y-3">
            {e.attachments.map((a) => (
              <li key={a.sha256} className="rounded-lg border border-slate-800 p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-medium text-slate-200">{a.filename}</span>
                  <span className="text-xs text-slate-500">{a.size_bytes} bytes</span>
                </div>
                <div className="mt-1 text-xs text-slate-400">declared {a.declared_mime} · expected {a.expected_mime || "?"} · content {a.detected_magic || "unknown"}</div>
                <div className="mt-1 break-all font-mono text-[11px] text-slate-500">sha256 {a.sha256}</div>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {a.flags.length ? a.flags.map((f) => (
                    <span key={f.code} className="flex items-center gap-1"><SeverityBadge severity={f.severity} /><span className="text-xs text-slate-300">{f.description}</span></span>
                  )) : <Badge tone="green">no static red flags</Badge>}
                </div>
              </li>
            ))}
          </ul>
        ) : <Empty>No attachments.</Empty>}
      </Card>

      <Card title="Body" subtitle="Shown as plain text. HTML is never rendered, so tracking pixels and scripts cannot run."
        right={e.body_html && (
          <button onClick={() => setShowHtml(!showHtml)} className="text-xs text-sky-400">{showHtml ? "show text" : "show HTML source"}</button>
        )} className="lg:col-span-2">
        <pre className="max-h-96 overflow-auto whitespace-pre-wrap rounded-lg bg-slate-950 p-3 font-mono text-xs text-slate-300">
          {showHtml ? e.body_html : e.body_text || "(empty body)"}
        </pre>
      </Card>

      <Card title={`URLs found (${e.urls.length})`} className="lg:col-span-2">
        {e.urls.length ? (
          <ul className="space-y-1 text-sm">
            {e.urls.map((u) => (
              <li key={u.url} className="break-all">
                <Mono>{u.url}</Mono>
                <span className="ml-2 text-xs text-slate-500">found in {u.sources.join(", ")}{u.display_texts.length ? ` · link text "${u.display_texts.join('", "')}"` : ""}</span>
              </li>
            ))}
          </ul>
        ) : <Empty>No URLs.</Empty>}
      </Card>
    </div>
  );
}
