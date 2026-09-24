import { useEffect, useState } from "react";
import UploadPage from "./pages/UploadPage.jsx";
import AnalysisPage from "./pages/AnalysisPage.jsx";

// Tiny hash router: #/ (upload) and #/analysis/<id>
function useRoute() {
  const [hash, setHash] = useState(window.location.hash);
  useEffect(() => {
    const onChange = () => setHash(window.location.hash);
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  const m = hash.match(/^#\/analysis\/([\w-]+)/);
  return m ? { page: "analysis", id: m[1] } : { page: "upload" };
}

export default function App() {
  const route = useRoute();
  return (
    <div className="min-h-screen">
      <header className="sticky top-0 z-20 border-b border-slate-800 bg-slate-950/90 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-3">
          <a href="#/" className="flex items-center gap-3">
            <img src="/favicon.svg" alt="" className="h-8 w-8" />
            <div>
              <div className="text-sm font-semibold text-slate-100">Email Threat Intelligence &amp; Forensics</div>
              <div className="text-xs text-slate-500">SIH26106 · AI-assisted detection, geolocation and forensic investigation</div>
            </div>
          </a>
          <a href="#/" className="rounded-lg border border-slate-700 px-3 py-1.5 text-sm text-slate-300 hover:border-sky-500 hover:text-sky-300">
            + New analysis
          </a>
        </div>
      </header>
      <main className="mx-auto max-w-7xl px-4 py-6">
        {route.page === "analysis" ? <AnalysisPage id={route.id} /> : <UploadPage />}
      </main>
      <footer className="mx-auto max-w-7xl px-4 pb-8 text-xs text-slate-600">
        Evidence-based decision support. It does not identify attackers. Geolocation is approximate; unknown does not mean safe.
      </footer>
    </div>
  );
}
