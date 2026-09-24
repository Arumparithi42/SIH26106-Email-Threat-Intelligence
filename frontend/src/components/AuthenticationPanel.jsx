import { Badge, Card, KV, Mono, StatusBadge } from "./ui.jsx";

function Mechanism({ name, r, explain, extra }) {
  return (
    <Card title={name} right={<StatusBadge status={r.status} />}>
      <p className="mb-3 text-xs text-slate-500">{explain}</p>
      <KV rows={[
        ["Result used", <span key="r" className="flex items-center gap-2"><StatusBadge status={r.status} /><span className="text-xs text-slate-400">{r.status_source === "receiver_reported" ? "from receiving server (Authentication-Results)" : "our independent check (live DNS)"}</span></span>],
        ["Independent check", <StatusBadge key="i" status={r.independent_check} />],
        ["Receiver-recorded", r.receiver_reported ? <StatusBadge key="rr" status={r.receiver_reported} /> : null],
        ...extra,
        ["Evidence", <span key="e" className="text-xs text-slate-300">{r.evidence}</span>],
      ]} />
    </Card>
  );
}

export default function AuthenticationPanel({ report }) {
  const a = report.header_forensics.authentication;
  const rr = a.receiver_reported || {};
  return (
    <div className="grid gap-5 lg:grid-cols-3">
      <Mechanism name="SPF" r={a.spf} explain="Is the server that delivered this email allowed to send for the envelope-sender (Return-Path) domain?"
        extra={[["Domain", a.spf.domain], ["Checked IP", a.spf.ip && <Mono key="ip">{a.spf.ip}</Mono>], ["SPF record", a.spf.record && <Mono key="rec">{a.spf.record}</Mono>]]} />
      <Mechanism name="DKIM" r={a.dkim} explain="Was the message cryptographically signed by a domain, and is it unmodified since signing?"
        extra={[["Signing domain", a.dkim.domain], ["Signatures", (a.dkim.signatures || []).map((s) => `d=${s.domain} s=${s.selector} → ${s.status}`).join("; ") || "none"]]} />
      <Mechanism name="DMARC" r={a.dmarc} explain="Does an SPF or DKIM pass align with the visible From domain, and what does the domain owner want done on failure?"
        extra={[["Policy", a.dmarc.policy ? <Badge key="p" tone="blue">p={a.dmarc.policy}</Badge> : "no policy"],
          ["SPF alignment", <StatusBadge key="sa" status={a.dmarc.spf_alignment} />], ["DKIM alignment", <StatusBadge key="da" status={a.dmarc.dkim_alignment} />],
          ["Record", a.dmarc.record && <Mono key="r">{a.dmarc.record}</Mono>]]} />
      <Card title="Receiver-recorded Authentication-Results" className="lg:col-span-3"
        subtitle="Recorded by the recipient's mail server at delivery time. Trusted only if added by the final receiving server, because senders can forge this header.">
        {rr.present ? (
          <KV rows={[
            ["Trusted", rr.trusted ? <Badge key="t" tone="green" icon="✓">YES: added by final receiver</Badge> : <Badge key="t" tone="amber" icon="⚠">NO: ignored</Badge>],
            ["authserv-id", rr.authserv_id], ["Raw", <Mono key="raw">{rr.raw || rr.received_spf_raw}</Mono>],
          ]} />
        ) : <p className="text-sm text-slate-500">No Authentication-Results header present.</p>}
        <p className="mt-3 text-xs text-slate-500">
          A single failure is evidence, not proof of phishing: forwarding and misconfiguration also break SPF/DKIM. A pass does not mean the email is safe
          (BEC often comes from genuine, authenticated accounts).
        </p>
      </Card>
    </div>
  );
}
