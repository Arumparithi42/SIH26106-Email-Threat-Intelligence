import { CircleMarker, MapContainer, Popup, TileLayer } from "react-leaflet";
import { Badge, Card, Empty, KV, Mono, ProviderResult, SignalBadge, StatusBadge } from "./ui.jsx";

const ROLE_LABEL = {
  sending_ip: "sending IP", relay_ip: "relay", private_ip: "private", url_ip: "IP in URL", url_host_ip: "link host",
  domain_resolved_ip: "domain A record", originating_client_ip: "originating client",
};

function GeoMap({ ips }) {
  const points = ips.filter((i) => i.geolocation.latitude != null && i.geolocation.longitude != null);
  if (!points.length)
    return <Empty>No coordinates available. City-level geolocation needs the MaxMind GeoLite2 City database (see README). Countries from other providers are shown in the table.</Empty>;
  return (
    <MapContainer center={[points[0].geolocation.latitude, points[0].geolocation.longitude]} zoom={2} style={{ height: 320 }} scrollWheelZoom={false}>
      <TileLayer attribution='&copy; OpenStreetMap contributors' url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />
      {points.map((ip) => (
        <CircleMarker key={ip.ip} center={[ip.geolocation.latitude, ip.geolocation.longitude]} radius={ip.roles.includes("sending_ip") ? 10 : 6}
          pathOptions={{ color: ip.roles.includes("sending_ip") ? "#f43f5e" : "#38bdf8", fillOpacity: 0.6 }}>
          <Popup>
            <b>{ip.ip}</b> ({ip.roles.map((r) => ROLE_LABEL[r] || r).join(", ")})<br />
            {[ip.geolocation.city, ip.geolocation.region, ip.geolocation.country].filter(Boolean).join(", ")}<br />
            accuracy ±{ip.geolocation.accuracy_radius_km ?? "?"} km (approximate infrastructure location)
          </Popup>
        </CircleMarker>
      ))}
    </MapContainer>
  );
}

function IpCard({ ip }) {
  const g = ip.geolocation, n = ip.network, an = ip.anonymization;
  const rep = ip.reputation;
  const tor = ip.providers.find((p) => p.provider === "tor_exit_list");
  return (
    <Card title={<span className="font-mono normal-case text-sky-200">{ip.ip}</span>}
      right={<div className="flex flex-wrap justify-end gap-1">{ip.roles.map((r) => <Badge key={r} tone={r === "sending_ip" ? "red" : "slate"}>{ROLE_LABEL[r] || r}</Badge>)}</div>}>
      {!ip.is_public ? <p className="text-sm text-slate-500">Private/reserved address: never sent to external services.</p> : (
        <div className="grid gap-4 md:grid-cols-2">
          <KV rows={[
            ["ASN", n.asn], ["Organisation", n.organization], ["ISP", n.isp], ["Network source", n.source],
            ["Location", [g.city, g.region, g.country || g.country_code].filter(Boolean).join(", ") || "unknown"],
            ["Coordinates", g.latitude != null ? `${g.latitude}, ${g.longitude} (±${g.accuracy_radius_km ?? "?"} km)` : null],
            ["Geo source", g.source],
          ]} />
          <div className="space-y-1.5 text-sm">
            {[["VPN", an.vpn], ["Proxy", an.proxy], ["Tor", an.tor], ["Hosting / data center", an.hosting]].map(([k, s]) => (
              <div key={k} className="flex items-center justify-between gap-2">
                <span className="text-slate-400">{k}</span>
                <span title={s.evidence.map((e) => `${e.source}.${e.field}=${e.value}`).join("\n")}><SignalBadge value={s.value} /></span>
              </div>
            ))}
            <div className="flex items-center justify-between"><span className="text-slate-400">Active VPN / Tor (IPQS premium)</span>
              <span className="text-xs text-slate-300">{String(an.active_vpn ?? "n/a")} / {String(an.active_tor ?? "n/a")}</span></div>
            <div className="flex items-center justify-between"><span className="text-slate-400">Connection type</span><span className="text-xs">{an.connection_type?.value || "unknown"}</span></div>
          </div>
          <div className="md:col-span-2">
            <table className="w-full text-sm">
              <thead><tr className="text-left text-xs text-slate-500"><th className="pb-1">Source</th><th>Result</th><th>Details</th></tr></thead>
              <tbody>
                {[["AbuseIPDB", rep.abuseipdb], ["VirusTotal", rep.virustotal], ["IPQualityScore", rep.ipqualityscore], ["Tor exit list", tor]].map(([name, r]) => (
                  <tr key={name} className="border-t border-slate-800 align-top">
                    <td className="py-1.5 text-slate-400">{name}</td>
                    <td className="py-1.5">
                      {r?.provider === "tor_exit_list" && r.status === "success"
                        ? (r.data.listed ? <Badge tone="red" icon="●">LISTED</Badge> : <Badge tone="green" icon="○">NOT LISTED</Badge>)
                        : <ProviderResult result={r} />}
                      {r?.cached && <span className="ml-1 text-[10px] text-slate-500">cached</span>}
                    </td>
                    <td className="py-1.5 text-xs text-slate-400">{r?.summary}{r?.provider === "ipqualityscore" && r.data?.fraud_score != null &&
                      <span className="block text-slate-500">IPQS fraud_score {r.data.fraud_score} (provider's own number, not used in our risk score)</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </Card>
  );
}

export default function IpIntelligence({ report }) {
  const ips = report.ip_intelligence;
  return (
    <div className="flex flex-col gap-5">
      <Card title="Geolocation (approximate infrastructure location)" subtitle="Location of servers / network exits, not of a person. A foreign location is not malicious by itself.">
        <GeoMap ips={ips} />
      </Card>
      {ips.length ? ips.map((ip) => <IpCard key={ip.ip} ip={ip} />) : <Empty>No IP addresses extracted.</Empty>}
      <p className="text-xs text-slate-500">VPN/proxy/Tor are anonymisation indicators, not proof of malicious intent. <StatusBadge status="skipped" label="NOT CONFIGURED" /> means the provider has no API key; <Mono>unknown</Mono> never means safe.</p>
    </div>
  );
}
