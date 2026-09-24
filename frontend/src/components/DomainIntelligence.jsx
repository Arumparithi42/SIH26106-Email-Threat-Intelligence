import { Badge, Card, Empty, KV, Mono, ProviderResult, StatusBadge } from "./ui.jsx";

const DNS_STATUS = { success: ["green", "RESOLVES"], nxdomain: ["orange", "NXDOMAIN (does not exist)"], unavailable: ["amber", "DNS UNAVAILABLE"], no_records: ["slate", "NO RECORDS"] };

export default function DomainIntelligence({ report }) {
  const domains = report.domain_intelligence;
  if (!domains.length) return <Empty>No domains extracted.</Empty>;
  return (
    <div className="grid gap-5 lg:grid-cols-2">
      {domains.map((d) => {
        const dns = d.dns || {};
        const [tone, label] = DNS_STATUS[dns.status] || ["slate", (dns.status || "unknown").toUpperCase()];
        const reg = d.registration || {};
        return (
          <Card key={d.domain} title={<span className="font-mono normal-case text-sky-200">{d.domain}</span>}
            right={<div className="flex flex-wrap justify-end gap-1">{d.roles.map((r) => <Badge key={r}>{r.replaceAll("_", " ")}</Badge>)}</div>}>
            <div className="mb-3 flex flex-wrap gap-1.5">
              <Badge tone={tone}>{label}</Badge>
              {d.lookalike_of && <Badge tone="red" icon="≈">LOOKS LIKE {d.lookalike_of}</Badge>}
              {d.reserved_tld && <Badge tone="blue">reserved demo TLD</Badge>}
            </div>
            <KV rows={[
              ["A", dns.a?.join(", ") || null], ["AAAA", dns.aaaa?.join(", ") || null], ["MX", dns.mx?.join(", ") || null],
              ["NS", dns.ns?.join(", ") || null], ["CNAME", dns.cname?.join(", ") || null],
              ["SPF", dns.spf && <Mono key="s">{dns.spf}</Mono>], ["DMARC", dns.dmarc && <Mono key="d">{dns.dmarc}</Mono>],
              ["Hostnames seen", d.hostnames?.join(", ") || null],
              ["Registration", <span key="r" className="flex items-center gap-2"><StatusBadge status={reg.status} />{reg.summary}</span>],
              ["Created", reg.created ? `${reg.created.slice(0, 10)} (${reg.age_days} days)` : null], ["Registrar", reg.registrar],
              ["VirusTotal", <span key="vt" className="flex items-center gap-2"><ProviderResult result={d.reputation?.virustotal} />
                <span className="text-xs text-slate-500">{d.reputation?.virustotal?.summary}</span></span>],
            ]} />
            <p className="mt-3 text-[11px] text-slate-500">Missing/redacted WHOIS data and new registration dates are context, not proof of malice.</p>
          </Card>
        );
      })}
    </div>
  );
}
