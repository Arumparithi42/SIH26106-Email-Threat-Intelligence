import { useEffect, useRef, useState } from "react";
import { api } from "../services/api.js";
import { Badge, Card, Empty, RiskBadge } from "../components/ui.jsx";

const STAGES = [
  "Email collection & parsing",
  "Threat detection (rules + ML)",
  "Header forensics · SPF / DKIM / DMARC",
  "Indicator extraction",
  "IP & domain intelligence",
  "Correlation graph",
  "Risk & confidence",
  "Forensic report",
];

function Progress({ running, done }) {
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (!running) return undefined;
    setTick(0);
    const t = setInterval(() => setTick((x) => x + 1), 450);
    return () => clearInterval(t);
  }, [running]);
  const active = done ? STAGES.length : Math.min(tick, STAGES.length - 1);
  return (
    <ol className="mt-4 grid gap-1.5 sm:grid-cols-2">
      {STAGES.map((s, i) => {
        const state = i < active ? "done" : i === active && running ? "active" : "pending";
        return (
          <li key={s} className="flex items-center gap-2 text-sm">
            <span className={`flex h-5 w-5 items-center justify-center rounded-full text-[11px] ${
              state === "done" ? "bg-emerald-500/20 text-emerald-300" : state === "active" ? "animate-pulse bg-sky-500/30 text-sky-200" : "bg-slate-800 text-slate-500"}`}>
              {state === "done" ? "✓" : i + 1}
            </span>
            <span className={state === "pending" ? "text-slate-500" : "text-slate-200"}>{s}</span>
            {state === "active" && <span className="text-xs text-sky-400">running…</span>}
          </li>
        );
      })}
    </ol>
  );
}

export default function UploadPage() {
  const [file, setFile] = useState(null);
  const [raw, setRaw] = useState("");
  const [mode, setMode] = useState("file");
  const [running, setRunning] = useState(false);
  const [error, setError] = useState(null);
  const [recent, setRecent] = useState([]);
  const [health, setHealth] = useState(null);
  const [drag, setDrag] = useState(false);
  const input = useRef(null);

  useEffect(() => {
    api.analyses().then(setRecent).catch(() => setRecent([]));
    api.health().then(setHealth).catch(() => setHealth(null));
  }, []);

  async function analyze() {
    setError(null);
    setRunning(true);
    try {
      const report = mode === "file" ? await api.analyzeFile(file) : await api.analyzeRaw(raw);
      window.location.hash = `#/analysis/${report.analysis_id}`;
    } catch (e) {
      setError(e.message);
    } finally {
      setRunning(false);
    }
  }

  const ready = mode === "file" ? !!file : raw.trim().length > 20;
  return (
    <div className="grid gap-6 lg:grid-cols-[3fr_2fr]">
      <Card title="1 · Upload email" subtitle="Upload a raw .eml file or paste the full source (headers + body). Content is treated as untrusted data: links are never visited and attachments are never opened.">
        <div className="mb-3 flex gap-2">
          {["file", "raw"].map((m) => (
            <button key={m} onClick={() => setMode(m)}
              className={`rounded-md px-3 py-1 text-sm ${mode === m ? "bg-sky-500/20 text-sky-200 ring-1 ring-sky-500/50" : "text-slate-400 hover:text-slate-200"}`}>
              {m === "file" ? ".eml file" : "Paste raw email"}
            </button>
          ))}
        </div>
        {mode === "file" ? (
          <div
            onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
            onDragLeave={() => setDrag(false)}
            onDrop={(e) => { e.preventDefault(); setDrag(false); setFile(e.dataTransfer.files[0] || null); }}
            onClick={() => input.current?.click()}
            className={`flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed p-10 text-center transition ${
              drag ? "border-sky-400 bg-sky-500/10" : "border-slate-700 hover:border-slate-500"}`}>
            <div className="text-3xl">✉</div>
            <div className="mt-2 text-sm text-slate-300">{file ? file.name : "Drop an .eml file here or click to choose"}</div>
            <div className="mt-1 text-xs text-slate-500">{file ? `${(file.size / 1024).toFixed(1)} KB` : `Max ${health?.max_upload_mb ?? 10} MB · try samples/phishing.eml`}</div>
            <input ref={input} type="file" accept=".eml,message/rfc822,.txt" className="hidden" onChange={(e) => setFile(e.target.files[0] || null)} />
          </div>
        ) : (
          <textarea value={raw} onChange={(e) => setRaw(e.target.value)} rows={12} spellCheck={false}
            placeholder={"From: sender@example.com\nTo: you@example.com\nSubject: ...\n\nBody..."}
            className="w-full rounded-lg border border-slate-700 bg-slate-950 p-3 font-mono text-xs text-slate-200 outline-none focus:border-sky-500" />
        )}
        <button disabled={!ready || running} onClick={analyze}
          className="mt-4 w-full rounded-lg bg-sky-600 py-2.5 text-sm font-semibold text-white shadow hover:bg-sky-500 disabled:cursor-not-allowed disabled:bg-slate-700 disabled:text-slate-400">
          {running ? "Analyzing…" : "Analyze Email"}
        </button>
        {(running || error) && <Progress running={running} done={false} />}
        {error && <p className="mt-3 rounded-lg bg-red-500/10 p-3 text-sm text-red-300">⚠ {error}</p>}
      </Card>

      <div className="flex flex-col gap-6">
        <Card title="Provider status" subtitle="Keys live only on the backend. Missing providers show 'Not configured'; the analysis still runs.">
          {health ? (
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(health.providers).map(([k, v]) => (
                <Badge key={k} tone={v ? "green" : "slate"} icon={v ? "✓" : "–"}>{k.replaceAll("_", " ")}: {v ? "configured" : "not configured"}</Badge>
              ))}
              <p className="mt-2 w-full text-xs text-slate-500">
                ML model {health.ml_model.model} · cross-validated macro-F1 {health.ml_model.cv_macro_f1} on a small synthetic dataset
              </p>
            </div>
          ) : <Empty>Backend not reachable at /api. Start it with <code>uvicorn app.main:app</code>.</Empty>}
        </Card>
        <Card title="Recent analyses">
          {recent.length ? (
            <ul className="divide-y divide-slate-800">
              {recent.slice(0, 12).map((a) => (
                <li key={a.analysis_id}>
                  <a href={`#/analysis/${a.analysis_id}`} className="flex items-center justify-between gap-3 py-2 hover:bg-slate-800/40">
                    <div className="min-w-0">
                      <div className="truncate text-sm text-slate-200">{a.subject || "(no subject)"}</div>
                      <div className="truncate text-xs text-slate-500">{a.from_address} · {a.filename || "raw"} · {new Date(a.created_at).toLocaleString()}</div>
                    </div>
                    <div className="flex shrink-0 items-center gap-1.5">
                      <RiskBadge level={a.risk_level} />
                    </div>
                  </a>
                </li>
              ))}
            </ul>
          ) : <Empty>No analyses yet.</Empty>}
        </Card>
      </div>
    </div>
  );
}

