// Shared UI primitives. Every status badge carries a TEXT label (never colour alone).

export function Card({ title, subtitle, right, children, className = "" }) {
  return (
    <section className={`rounded-xl border border-slate-800 bg-slate-900/60 p-4 shadow-sm ${className}`}>
      {(title || right) && (
        <header className="mb-3 flex items-start justify-between gap-3">
          <div>
            {title && <h3 className="text-sm font-semibold uppercase tracking-wide text-slate-300">{title}</h3>}
            {subtitle && <p className="mt-0.5 text-xs text-slate-500">{subtitle}</p>}
          </div>
          {right}
        </header>
      )}
      {children}
    </section>
  );
}

const TONES = {
  red: "bg-red-500/15 text-red-300 ring-red-500/40",
  darkred: "bg-rose-900/40 text-rose-200 ring-rose-500/60",
  orange: "bg-orange-500/15 text-orange-300 ring-orange-500/40",
  amber: "bg-amber-500/15 text-amber-300 ring-amber-500/40",
  green: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/40",
  blue: "bg-sky-500/15 text-sky-300 ring-sky-500/40",
  violet: "bg-violet-500/15 text-violet-300 ring-violet-500/40",
  slate: "bg-slate-500/15 text-slate-300 ring-slate-500/40",
};

export function Badge({ tone = "slate", icon, children, title }) {
  return (
    <span title={title} className={`inline-flex items-center gap-1 whitespace-nowrap rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${TONES[tone]}`}>
      {icon && <span aria-hidden>{icon}</span>}
      {children}
    </span>
  );
}

const STATUS = {
  pass: ["green", "✓", "PASS"], fail: ["red", "✗", "FAIL"], softfail: ["orange", "!", "SOFTFAIL"], neutral: ["slate", "○", "NEUTRAL"],
  none: ["slate", "–", "NONE"], unknown: ["slate", "?", "UNKNOWN"], error: ["amber", "⚠", "ERROR"], not_applicable: ["slate", "–", "N/A"],
  success: ["green", "✓", "OK"], skipped: ["slate", "–", "NOT CONFIGURED / SKIPPED"], rate_limited: ["amber", "⏸", "RATE LIMITED"],
  unavailable: ["amber", "⚠", "UNAVAILABLE"],
};

export function StatusBadge({ status, label }) {
  const [tone, icon, text] = STATUS[status] || ["slate", "?", (status || "unknown").toUpperCase()];
  return <Badge tone={tone} icon={icon}>{label || text}</Badge>;
}

const SEV = { critical: ["darkred", "‼"], high: ["red", "▲"], medium: ["orange", "◆"], low: ["amber", "▽"], info: ["blue", "i"] };
export function SeverityBadge({ severity }) {
  const [tone, icon] = SEV[severity] || ["slate", "?"];
  return <Badge tone={tone} icon={icon}>{severity?.toUpperCase()}</Badge>;
}

const RISK = { LOW: "green", MEDIUM: "orange", HIGH: "red", CRITICAL: "darkred" };
export function RiskBadge({ level, big }) {
  return (
    <span className={`inline-flex items-center rounded-lg font-bold ring-1 ring-inset ${TONES[RISK[level] || "slate"]} ${big ? "px-3 py-1 text-lg" : "px-2 py-0.5 text-xs"}`}>
      {level}
    </span>
  );
}

export function ConfidenceBadge({ level }) {
  return <Badge tone="violet" icon="◎">CONFIDENCE {String(level).toUpperCase()}</Badge>;
}

const SIGNAL = { detected: ["red", "●", "DETECTED"], not_detected: ["green", "○", "NOT DETECTED"], unknown: ["slate", "?", "UNKNOWN"] };
export function SignalBadge({ value }) {
  const [tone, icon, text] = SIGNAL[value] || SIGNAL.unknown;
  return <Badge tone={tone} icon={icon}>{text}</Badge>;
}

const VERDICT = { malicious: ["red", "MALICIOUS"], suspicious: ["orange", "SUSPICIOUS"], no_detections: ["green", "NO DETECTIONS"], unknown: ["slate", "UNKNOWN"] };
export function ProviderResult({ result }) {
  if (!result) return <Badge>NOT QUERIED</Badge>;
  if (result.status !== "success") return <StatusBadge status={result.status} label={result.summary === "Not configured" ? "NOT CONFIGURED" : undefined} />;
  const [tone, text] = VERDICT[result.verdict] || VERDICT.unknown;
  return <Badge tone={tone}>{text}</Badge>;
}

export function KV({ rows }) {
  return (
    <dl className="grid grid-cols-[minmax(110px,max-content)_1fr] gap-x-4 gap-y-1.5 text-sm">
      {rows.filter(Boolean).map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-slate-500">{k}</dt>
          <dd className="break-all text-slate-200">{v ?? <span className="text-slate-600">—</span>}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Empty({ children }) {
  return <p className="rounded-lg border border-dashed border-slate-700 p-4 text-center text-sm text-slate-500">{children}</p>;
}

export function Mono({ children }) {
  return <span className="font-mono text-[13px] text-sky-200">{children}</span>;
}

export const TYPE_TAG = {
  observed_fact: ["blue", "OBSERVED FACT"],
  analytical_finding: ["violet", "ANALYTICAL FINDING"],
  threat_intel: ["amber", "THREAT INTEL RESULT"],
};
export function EvidenceTypeBadge({ type }) {
  const [tone, text] = TYPE_TAG[type] || ["slate", type];
  return <Badge tone={tone}>{text}</Badge>;
}
