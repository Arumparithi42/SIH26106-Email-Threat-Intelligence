"""The integrated workflow. One call = one complete investigation:

collect -> threat detection -> header forensics -> indicators -> IP/domain/URL
intelligence -> correlation graph -> findings -> risk & confidence -> timeline
-> persist -> PDF report.

Each stage's output is the next stage's input. A failing stage is recorded in the
timeline and replaced by an empty result, so the rest of the analysis continues.
"""
from __future__ import annotations

import logging
import uuid
from pathlib import Path

from app.core.config import get_settings
from app.core.utils import iso, sha256_hex, utcnow
from app.schemas.report import SCHEMA_VERSION, AnalysisReport, TimelineEvent
from app.services.correlation.graph import build_graph
from app.services.email_parser.attachments import attachment_findings
from app.services.email_parser.parser import parse_email
from app.services.header_forensics.forensics import analyze_headers
from app.services.ip_domain_intelligence.indicators import extract_indicators
from app.services.ip_domain_intelligence.intelligence import gather_intelligence
from app.services.reporting.pdf_report import build_pdf
from app.services.repository import save_report
from app.services.risk_engine.engine import assess_risk
from app.services.threat_detection.detector import detect_threats

log = logging.getLogger(__name__)

BASE_LIMITATIONS = [
    "This is AI-assisted threat detection and forensic investigation: it presents evidence and a risk assessment, it does not identify the attacker.",
    "Geolocation is the approximate location of network infrastructure (servers, VPN exits), not of a person.",
    "Threat intelligence is incomplete: 'unknown' or 'no detections' never means safe; new infrastructure often has no history.",
    "Received headers below the recipient's own servers can be forged by the sender.",
    "SPF/DKIM/DMARC are re-checked with current DNS; DNS may have changed since delivery. Receiver-recorded results are shown separately.",
    "The ML classifier is trained on a small synthetic dataset and is only one supporting signal.",
    "URLs are never visited and attachments are never opened, so payload behaviour is not analysed (no sandboxing).",
]


class Timeline:
    def __init__(self) -> None:
        self.events: list[TimelineEvent] = []

    def add(self, stage: str, event: str, status: str = "completed", detail: str | None = None) -> None:
        self.events.append(TimelineEvent(timestamp=iso(utcnow()), kind="investigation", stage=stage, event=event, status=status, detail=detail))


def _email_events(parsed: dict, header: dict) -> list[TimelineEvent]:
    out = []
    if parsed["headers"].get("date_iso"):
        out.append(TimelineEvent(timestamp=parsed["headers"]["date_iso"], kind="email", stage="email", event="Email composed (Date header, set by sender)",
                                 status="observed", detail=parsed["headers"].get("date")))
    for hop in header.get("received_chain", []):
        out.append(TimelineEvent(timestamp=hop.get("timestamp"), kind="email", stage="routing",
                                 event=f"Hop {hop['hop']}: {hop.get('hostname') or hop.get('ip') or 'unknown'} -> {hop.get('server') or 'unknown'}",
                                 status="observed", detail=(f"+{hop['time_delta_seconds']} s" if hop.get("time_delta_seconds") is not None else None)))
    return sorted(out, key=lambda e: e.timestamp or "")


def analyze_email(raw: bytes, filename: str | None = None) -> dict:
    settings = get_settings()
    analysis_id = "an_" + uuid.uuid4().hex[:12]
    created = iso(utcnow())
    tl = Timeline()
    tl.add("collection", "Email received", detail=f"{filename or 'raw text'}, {len(raw)} bytes, SHA-256 {sha256_hex(raw)[:16]}...")

    parsed = parse_email(raw)  # invalid input -> EmailParseError (HTTP 422)
    tl.add("collection", "Email parsed", detail=f"{len(parsed['urls'])} URL(s), {len(parsed['attachments'])} attachment(s), {len(parsed['received'])} Received header(s)")

    try:
        threat, f_threat = detect_threats(parsed)
        tl.add("threat_detection", "Threat detection completed", detail=f"rules: {threat['rule_category'] or 'no category'}; ML: {threat['ml'].get('predicted_category')} p={threat['ml'].get('probability')}")
    except Exception as exc:  # noqa: BLE001
        log.exception("threat detection failed")
        threat, f_threat = {"rule_matches": [], "matched_groups": [], "rule_category": None, "impersonation_indicators": [], "ml": {"status": "error"}, "summary": {}}, []
        tl.add("threat_detection", "Threat detection failed", "error", str(exc)[:200])

    try:
        header, f_header = analyze_headers(parsed, raw)
        tl.add("header_forensics", "Headers analyzed", detail=f"{len(header['received_chain'])} hop(s), {len(header['anomalies'])} anomaly(ies)")
        auth = header["authentication"]
        for mech in ("spf", "dkim", "dmarc"):
            tl.add("header_forensics", f"{mech.upper()} checked", detail=f"{auth[mech]['status']} ({auth[mech]['status_source']})")
    except Exception as exc:  # noqa: BLE001
        log.exception("header forensics failed")
        header, f_header = {"important_headers": {}, "identity": {"domains": {}, "comparisons": []}, "received_chain": [], "routing_path": [], "anomalies": [],
                            "sending_ip": {"ip": None, "method": "error"},
                            "authentication": {m: {"status": "error", "status_source": "independent_check", "evidence": "stage failed"} for m in ("spf", "dkim", "dmarc")}
                            | {"receiver_reported": {}}}, []
        tl.add("header_forensics", "Header analysis failed", "error", str(exc)[:200])

    ind = extract_indicators(parsed, header)
    tl.add("indicators", "URLs and indicators extracted", detail=f"{len(ind.ips)} IP(s), {len(ind.domains)} domain(s), {len(ind.urls)} URL(s)")

    try:
        intel = gather_intelligence(ind, parsed, settings)
        stats = intel["provider_stats"]
        tl.add("ip_intelligence", "IP intelligence completed", detail=f"{len(intel['ip_intelligence'])} IP(s); " + ", ".join(
            f"{p}: {'/'.join(f'{k} {v}' for k, v in s.items())}" for p, s in stats.items() if p in ("abuseipdb", "virustotal", "ipqualityscore", "maxmind_geolite2", "tor_exit_list")))
        tl.add("domain_intelligence", "Domain intelligence completed", detail=f"{len(intel['domain_intelligence'])} domain(s) (DNS + RDAP)")
    except Exception as exc:  # noqa: BLE001
        log.exception("intelligence failed")
        intel = {"ip_intelligence": [], "domain_intelligence": [], "url_analysis": [], "findings": [], "provider_stats": {}}
        tl.add("ip_intelligence", "IP/domain intelligence failed", "error", str(exc)[:200])

    findings = f_threat + f_header + intel["findings"] + attachment_findings(parsed["attachments"])
    flagged = {r: f.severity for f in findings if f.severity in ("medium", "high", "critical") for r in f.related_indicators}
    try:
        correlation, f_corr = build_graph(analysis_id, parsed, header, intel, flagged)
        findings += f_corr
        tl.add("correlation", "Threat graph generated", detail=f"{correlation['metrics']['node_count']} nodes, {correlation['metrics']['edge_count']} edges, "
               f"{len(correlation['related_analyses'])} related earlier analysis(es)")
    except Exception as exc:  # noqa: BLE001
        log.exception("graph failed")
        correlation = {"nodes": [], "edges": [], "metrics": {}, "related_analyses": []}
        tl.add("correlation", "Threat graph failed", "error", str(exc)[:200])

    unique, seen = [], set()
    for f in findings:
        if f.finding_id not in seen:
            seen.add(f.finding_id)
            unique.append(f)
    findings = unique

    risk = assess_risk(findings, threat, header, intel["provider_stats"])
    tl.add("risk", "Risk calculated", detail=f"{risk.risk_level} (score {risk.risk_score}), confidence {risk.confidence}, classification {risk.classification}")

    configured = settings.provider_configuration()
    limitations = list(BASE_LIMITATIONS)
    missing = [p for p in ("virustotal", "abuseipdb", "ipqualityscore", "google_safe_browsing") if not configured[p]]
    if missing:
        limitations.append("Not configured in this run (results 'skipped'): " + ", ".join(missing) + ".")
    if not (configured["maxmind_city"] or configured["maxmind_asn"]):
        limitations.append("MaxMind GeoLite2 databases not installed: city/coordinates unavailable.")

    tl.add("reporting", "Forensic report generated", detail="PDF")
    report = AnalysisReport(
        analysis_id=analysis_id, created_at=created,
        input={"filename": filename, "sha256": parsed["sha256"], "size_bytes": parsed["size_bytes"]},
        email={k: parsed[k] for k in ("headers", "raw_headers", "mime", "body_text", "body_html", "body_truncated", "urls", "attachments",
                                       "authentication_results", "dkim_signatures", "received")},
        threat_detection=threat, header_forensics=header, indicators=ind.as_lists(),
        ip_intelligence=intel["ip_intelligence"], domain_intelligence=intel["domain_intelligence"],
        url_analysis=intel["url_analysis"], attachment_analysis=parsed["attachments"],
        correlation=correlation, findings=findings, risk_assessment=risk,
        timeline=_email_events(parsed, header) + tl.events,
        provider_status={"configured": configured, "lookup_stats": intel["provider_stats"]},
        report={"format": "pdf", "generated_at": tl.events[-1].timestamp, "download_url": f"/api/analysis/{analysis_id}/report"},
        limitations=limitations,
    ).model_dump(mode="json")

    try:
        pdf = build_pdf(report)
        path = Path(settings.reports_dir)
        path.mkdir(parents=True, exist_ok=True)
        (path / f"{analysis_id}.pdf").write_bytes(pdf)
        report["report"]["sha256"] = sha256_hex(pdf)
        report["report"]["size_bytes"] = len(pdf)
    except Exception as exc:  # noqa: BLE001
        log.exception("pdf generation failed")
        report["report"]["error"] = str(exc)[:200]
        report["timeline"][-1]["status"] = "error"
    save_report(report)
    return report
