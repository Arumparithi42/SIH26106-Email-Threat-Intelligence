import { useEffect, useRef, useState } from "react";
import cytoscape from "cytoscape";
import { Badge, Card, Mono } from "./ui.jsx";

const STYLE = {
  email: ["#38bdf8", "round-rectangle"], email_address: ["#a78bfa", "ellipse"], domain: ["#34d399", "round-diamond"],
  ip: ["#fb923c", "hexagon"], url: ["#f472b6", "round-tag"], attachment: ["#facc15", "rectangle"], asn: ["#94a3b8", "barrel"],
  organization: ["#64748b", "barrel"], threat_intel: ["#ef4444", "star"],
};
const LEGEND = Object.entries(STYLE);

export default function ThreatGraph({ report }) {
  const el = useRef(null);
  const [selected, setSelected] = useState(null);
  const { nodes, edges, metrics, related_analyses: related } = report.correlation;

  useEffect(() => {
    if (!el.current) return undefined;
    const cy = cytoscape({
      container: el.current,
      elements: [
        ...nodes.map((n) => ({ data: { id: n.id, label: n.label.length > 32 ? n.label.slice(0, 30) + "…" : n.label, type: n.type, flagged: n.data?.risk ? 1 : 0, previous: n.data?.previous_analysis ? 1 : 0, raw: n } })),
        ...edges.map((e, i) => ({ data: { id: `e${i}`, source: e.source, target: e.target, label: e.relation } })),
      ],
      style: [
        { selector: "node", style: {
          label: "data(label)", color: "#cbd5e1", "font-size": 9, "text-valign": "bottom", "text-margin-y": 4, width: 26, height: 26,
          "background-color": (n) => (STYLE[n.data("type")] || ["#94a3b8"])[0], shape: (n) => (STYLE[n.data("type")] || [0, "ellipse"])[1],
          "border-width": (n) => (n.data("flagged") ? 3 : 0), "border-color": "#ef4444",
        } },
        { selector: "node[previous = 1]", style: { "background-opacity": 0.4, "border-style": "dashed", "border-width": 2, "border-color": "#94a3b8" } },
        { selector: "node[type = 'email']", style: { width: 38, height: 38 } },
        { selector: "edge", style: {
          width: 1.2, "line-color": "#475569", "target-arrow-color": "#475569", "target-arrow-shape": "triangle", "curve-style": "bezier",
          label: "data(label)", "font-size": 7, color: "#64748b", "text-rotation": "autorotate",
        } },
        { selector: "edge[label = 'MATCHES_THREAT_INTEL']", style: { "line-color": "#ef4444", "target-arrow-color": "#ef4444" } },
        { selector: "edge[label = 'SEEN_IN']", style: { "line-style": "dashed" } },
        { selector: ":selected", style: { "border-width": 3, "border-color": "#f8fafc" } },
      ],
      layout: { name: "cose", animate: false, nodeRepulsion: 9000, idealEdgeLength: 90, padding: 20 },
      wheelSensitivity: 0.25,
    });
    cy.on("tap", "node", (evt) => setSelected(evt.target.data("raw")));
    cy.on("tap", (evt) => { if (evt.target === cy) setSelected(null); });
    return () => cy.destroy();
  }, [nodes, edges]);

  return (
    <div className="grid gap-5 lg:grid-cols-[3fr_1fr]">
      <Card title="Correlation / threat graph" subtitle="Nodes use stable indicator ids so the same IP/domain links across investigations. Red border = involved in a medium+ finding. Click a node for details.">
        <div ref={el} className="h-[560px] w-full rounded-lg bg-slate-950" />
        <div className="mt-3 flex flex-wrap gap-2">
          {LEGEND.map(([t, [c]]) => <span key={t} className="flex items-center gap-1 text-xs text-slate-400"><span className="h-3 w-3 rounded-sm" style={{ background: c }} />{t.replace("_", " ")}</span>)}
        </div>
      </Card>
      <div className="flex flex-col gap-5">
        <Card title="Selected node">
          {selected ? (
            <div className="space-y-2 text-sm">
              <Badge tone="blue">{selected.type}</Badge>
              <div className="break-all"><Mono>{selected.id}</Mono></div>
              <pre className="max-h-64 overflow-auto whitespace-pre-wrap rounded bg-slate-950 p-2 text-[11px] text-slate-400">{JSON.stringify(selected.data, null, 2)}</pre>
            </div>
          ) : <p className="text-sm text-slate-500">Click a node.</p>}
        </Card>
        <Card title="Graph metrics">
          <div className="space-y-1 text-sm text-slate-300">
            <div>{metrics.node_count} nodes · {metrics.edge_count} relationships</div>
            <div>{metrics.threat_intel_matches} threat-intel match(es)</div>
            <div className="text-xs text-slate-500">Pivot indicators (most connected):</div>
            <ul className="text-xs">{(metrics.pivot_indicators || []).map((p) => <li key={p}><Mono>{p}</Mono></li>)}</ul>
          </div>
        </Card>
        <Card title="Related earlier analyses" subtitle="Shared IPs/domains/URLs/files (recipient's own infrastructure excluded).">
          {related?.length ? (
            <ul className="space-y-2 text-sm">
              {related.map((r) => (
                <li key={r.analysis_id}>
                  <a href={`#/analysis/${r.analysis_id}`} className="text-sky-300 hover:underline">{r.subject || r.analysis_id}</a>
                  <span className="ml-1 text-xs text-slate-500">({r.risk_level})</span>
                  <div className="text-xs text-slate-500">{r.shared_indicators.join(", ")}</div>
                </li>
              ))}
            </ul>
          ) : <p className="text-sm text-slate-500">None found in the local database.</p>}
        </Card>
      </div>
    </div>
  );
}
