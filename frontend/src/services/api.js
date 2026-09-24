// All calls go to our FastAPI backend. External threat-intel APIs are called server-side only.
const BASE = import.meta.env.VITE_API_BASE || "/api";

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, options);
  if (!res.ok) {
    let detail = res.statusText;
    try {
      detail = (await res.json()).detail || detail;
    } catch {
      /* not JSON */
    }
    throw new Error(`${res.status}: ${detail}`);
  }
  return res.json();
}

export const api = {
  health: () => request("/health"),
  model: () => request("/model"),
  analyses: () => request("/analyses"),
  analysis: (id) => request(`/analysis/${id}`),
  analyzeFile: (file) => {
    const form = new FormData();
    form.append("file", file);
    return request("/analyze/email", { method: "POST", body: form });
  },
  analyzeRaw: (raw) => {
    const form = new FormData();
    form.append("raw_email", raw);
    return request("/analyze/email", { method: "POST", body: form });
  },
  reportUrl: (id) => `${BASE}/analysis/${id}/report`,
};
