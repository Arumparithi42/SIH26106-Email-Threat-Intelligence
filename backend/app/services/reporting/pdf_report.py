"""Stage 7 - Forensic PDF report (ReportLab).

Every section is labelled as one of:
  OBSERVED FACT              - read directly from the email / DNS
  ANALYTICAL FINDING         - our interpretation / rules / model
  THREAT INTELLIGENCE RESULT - statements made by external sources
"""
from __future__ import annotations

import io
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

TAG_COLORS = {"OBSERVED FACT": "#1d4ed8", "ANALYTICAL FINDING": "#7c3aed", "THREAT INTELLIGENCE RESULT": "#b45309"}
RISK_COLORS = {"LOW": "#15803d", "MEDIUM": "#ca8a04", "HIGH": "#dc2626", "CRITICAL": "#7f1d1d"}

_ss = getSampleStyleSheet()
H1 = ParagraphStyle("h1", parent=_ss["Heading1"], fontSize=16, spaceAfter=6)
H2 = ParagraphStyle("h2", parent=_ss["Heading2"], fontSize=12.5, spaceBefore=10, spaceAfter=4, textColor=colors.HexColor("#0f172a"))
BODY = ParagraphStyle("body", parent=_ss["BodyText"], fontSize=8.8, leading=11.5, alignment=TA_LEFT)
SMALL = ParagraphStyle("small", parent=BODY, fontSize=7.6, leading=9.5, textColor=colors.HexColor("#334155"))
CELL = ParagraphStyle("cell", parent=BODY, fontSize=7.6, leading=9.2)


def _p(text, style=BODY) -> Paragraph:
    return Paragraph(escape(str(text if text is not None else "-")), style)


def _tag(label: str) -> Paragraph:
    return Paragraph(f'<font color="{TAG_COLORS[label]}"><b>[{label}]</b></font>', SMALL)


def _table(rows: list[list], widths: list[float] | None = None, header: bool = True) -> Table:
    data = [[c if isinstance(c, Paragraph) else _p(c, CELL) for c in r] for r in rows]
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")), ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3)]
    if header:
        style.append(("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")))
    t.setStyle(TableStyle(style))
    return t


def _addr(a: dict | None) -> str:
    return (a or {}).get("raw") or (a or {}).get("address") or "-"


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#64748b"))
    canvas.drawString(15 * mm, 10 * mm, "SIH26106 - AI-assisted email threat detection & forensic investigation. Evidence-based; not an attribution of the attacker.")
    canvas.drawRightString(195 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def build_pdf(report: dict) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=14 * mm, bottomMargin=16 * mm,
                            title=f"Forensic report {report['analysis_id']}", author="SIH26106 Email Threat Intelligence")
    W = doc.width
    s: list = []
    email, risk, hf = report["email"], report["risk_assessment"], report["header_forensics"]
    h = email["headers"]
    color = RISK_COLORS.get(risk["risk_level"], "#000000")

    s += [Paragraph("Email Forensic Investigation Report", H1),
          _p(f"Analysis ID: {report['analysis_id']}   |   Generated: {report['report'].get('generated_at')}   |   Schema {report['schema_version']}", SMALL),
          _p(f"Input: {report['input'].get('filename') or 'raw text'}  |  SHA-256 {report['input']['sha256']}  |  {report['input']['size_bytes']} bytes", SMALL),
          Spacer(1, 6)]

    # ---- executive summary
    s.append(Paragraph("1. Executive summary", H2))
    s.append(_tag("ANALYTICAL FINDING"))
    s.append(Paragraph(f'Risk: <font color="{color}"><b>{risk["risk_level"]}</b></font> (score {risk["risk_score"]}/100) &nbsp;&nbsp; '
                       f'Confidence: <b>{risk["confidence"]}</b> &nbsp;&nbsp; Classification: <b>{escape(risk["classification"])}</b>', BODY))
    for r in risk["reasons"][:6]:
        s.append(_p(f"- {r}"))
    if risk["caps_applied"]:
        s.append(_p("Caps applied: " + "; ".join(risk["caps_applied"]), SMALL))
    s.append(_p("Method: " + risk["method"], SMALL))
    ind = report["indicators"]
    s.append(_p(f"Indicators: {len(ind['ips'])} IPs, {len(ind['domains'])} domains, {len(ind['urls'])} URLs, {len(ind['attachments'])} attachments; "
                f"{len(report['findings'])} findings.", SMALL))

    # ---- email summary
    s.append(Paragraph("2. Email summary", H2))
    s.append(_tag("OBSERVED FACT"))
    s.append(_table([["Field", "Value"], ["From", _addr(h.get("from"))], ["To", ", ".join(a["address"] for a in h.get("to") or []) or "-"],
                     ["Cc", ", ".join(a["address"] for a in h.get("cc") or []) or "-"], ["Subject", h.get("subject")], ["Date", h.get("date")],
                     ["Reply-To", _addr(h.get("reply_to"))], ["Return-Path", _addr(h.get("return_path"))], ["Message-ID", h.get("message_id")],
                     ["X-Mailer / User-Agent", h.get("x_mailer") or h.get("user_agent")]], [35 * mm, W - 35 * mm]))
    body = (email.get("body_text") or "")[:1200]
    s += [Spacer(1, 3), _p("Body excerpt (first 1200 characters, rendered as plain text):", SMALL), _p(body, SMALL)]

    # ---- threat detection
    td = report["threat_detection"]
    s.append(Paragraph("3. Threat detection (content + ML)", H2))
    s.append(_tag("ANALYTICAL FINDING"))
    ml = td.get("ml") or {}
    s.append(_p(f"Rule category: {td.get('rule_category') or 'none'}; ML ({ml.get('model')}): {ml.get('predicted_category')} p={ml.get('probability')}. "
                "The ML model is trained on a small synthetic dataset and is a supporting signal only."))
    if td.get("rule_matches"):
        s.append(_table([["Rule", "Group", "Matched text"]] + [[m["rule_id"] + " " + m["label"], m["group"], m["snippet"]] for m in td["rule_matches"]],
                        [45 * mm, 28 * mm, W - 73 * mm]))

    # ---- authentication
    auth = hf["authentication"]
    s.append(Paragraph("4. SPF / DKIM / DMARC", H2))
    s.append(_tag("OBSERVED FACT"))
    s.append(_table([["Check", "Result", "Source", "Details"],
                     ["SPF", auth["spf"]["status"].upper(), auth["spf"]["status_source"], f"domain {auth['spf'].get('domain')}, IP {auth['spf'].get('ip')}. {auth['spf']['evidence']}"],
                     ["DKIM", auth["dkim"]["status"].upper(), auth["dkim"]["status_source"], auth["dkim"]["evidence"]],
                     ["DMARC", auth["dmarc"]["status"].upper(), auth["dmarc"]["status_source"],
                      f"policy {auth['dmarc'].get('policy')}; SPF align {auth['dmarc'].get('spf_alignment')}; DKIM align {auth['dmarc'].get('dkim_alignment')}. {auth['dmarc']['evidence']}"]],
                    [16 * mm, 18 * mm, 30 * mm, W - 64 * mm]))
    s.append(_p("An authentication failure is evidence, not proof of phishing (forwarding and misconfiguration also cause failures).", SMALL))

    # ---- header analysis + received chain
    s.append(Paragraph("5. Header analysis and Received chain", H2))
    s.append(_tag("OBSERVED FACT"))
    comps = hf["identity"]["comparisons"]
    if comps:
        s.append(_table([["Header", "Domain", "Aligned with From"]] + [[c["field"], c["domain"], "yes" if c["aligned_with_from"] else "NO"] for c in comps],
                        [40 * mm, 80 * mm, W - 120 * mm]))
    s.append(_p(f"Sending IP used for SPF: {hf['sending_ip'].get('ip')} ({hf['sending_ip'].get('method')})", SMALL))
    hops = hf["received_chain"]
    if hops:
        s.append(_table([["Hop", "From (host / IP)", "By (server)", "Timestamp (UTC)", "Delta s", "Trust"]] +
                        [[x["hop"], f"{x.get('hostname') or '-'} / {x.get('ip') or '-'}", x.get("server"), x.get("timestamp"), x.get("time_delta_seconds"), x["trust"]] for x in hops],
                        [10 * mm, 48 * mm, 40 * mm, 34 * mm, 14 * mm, W - 146 * mm]))
    if hf["anomalies"]:
        s.append(_tag("ANALYTICAL FINDING"))
        for a in hf["anomalies"]:
            s.append(_p(f"- {a['description']} - {a['interpretation']}", SMALL))

    # ---- IP intelligence
    s.append(Paragraph("6. IP intelligence", H2))
    s.append(_tag("THREAT INTELLIGENCE RESULT"))
    rows = [["IP / roles", "Network", "Location (approx.)", "VPN / Proxy / Tor", "Reputation"]]
    for ip in report["ip_intelligence"]:
        an, g, n = ip["anonymization"], ip["geolocation"], ip["network"]
        reps = "; ".join(f"{k}: {v['status']}{'/' + v['verdict'] if v['status'] == 'success' else ''} {v.get('summary', '')}"[:120] for k, v in ip["reputation"].items())
        rows.append([f"{ip['ip']}\n{', '.join(ip['roles'])}", f"{n.get('asn') or '-'} {n.get('organization') or n.get('isp') or ''}",
                     ", ".join(x for x in (g.get("city"), g.get("region"), g.get("country") or g.get("country_code")) if x) or "unknown",
                     f"{an['vpn']['value']} / {an['proxy']['value']} / {an['tor']['value']}", reps or "-"])
    s.append(_table(rows, [34 * mm, 34 * mm, 28 * mm, 30 * mm, W - 126 * mm]))
    s.append(_p("Geolocation is the approximate location of network infrastructure. VPN/proxy/Tor are indicators, not proof. 'unknown' does not mean safe.", SMALL))

    # ---- domain intelligence
    s.append(Paragraph("7. Domain intelligence", H2))
    s.append(_tag("OBSERVED FACT"))
    rows = [["Domain / roles", "DNS", "Registration (RDAP)", "Reputation"]]
    for d in report["domain_intelligence"]:
        dn, reg = d["dns"], d["registration"]
        rows.append([f"{d['domain']}\n{', '.join(d['roles'])}" + (f"\nlooks like {d['lookalike_of']}" if d.get("lookalike_of") else ""),
                     f"status {dn.get('status')}; A {', '.join(dn.get('a', [])[:3]) or '-'}; MX {', '.join(dn.get('mx', [])[:2]) or '-'}; NS {', '.join(dn.get('ns', [])[:2]) or '-'}",
                     reg.get("summary") or reg.get("status"),
                     "; ".join(f"{k}: {v['status']} {v.get('summary', '')}" for k, v in d["reputation"].items()) or "-"])
    s.append(_table(rows, [40 * mm, 55 * mm, 40 * mm, W - 135 * mm]))

    # ---- URL analysis
    s.append(Paragraph("8. URL analysis", H2))
    s.append(_tag("ANALYTICAL FINDING"))
    rows = [["URL", "Domain", "Characteristics", "Threat intelligence"]]
    for u in report["url_analysis"]:
        rows.append([u["url"][:110], u.get("domain") or u.get("hostname"), ", ".join(c["code"] for c in u.get("characteristics", [])) or "-",
                     "; ".join(f"{k}: {v['status']}/{v['verdict']}" for k, v in (u.get("reputation") or {}).items()) or "-"])
    s.append(_table(rows, [62 * mm, 30 * mm, 45 * mm, W - 137 * mm]) if len(rows) > 1 else _p("No URLs found."))
    s.append(_p("URLs were analysed passively and never visited.", SMALL))

    # ---- attachments
    s.append(Paragraph("9. Attachment analysis", H2))
    s.append(_tag("OBSERVED FACT"))
    atts = report["attachment_analysis"]
    if atts:
        s.append(_table([["Filename", "MIME / magic", "Size", "SHA-256", "Flags"]] +
                        [[a["filename"], f"{a['declared_mime']} / {a.get('detected_magic') or '-'}", a["size_bytes"], a["sha256"], ", ".join(f["code"] for f in a["flags"]) or "-"] for a in atts],
                        [32 * mm, 32 * mm, 14 * mm, 60 * mm, W - 138 * mm]))
        s.append(_p("Attachments were hashed in memory only; never opened, saved or executed.", SMALL))
    else:
        s.append(_p("No attachments."))

    # ---- threat intel summary
    s.append(Paragraph("10. Threat intelligence sources queried", H2))
    s.append(_tag("THREAT INTELLIGENCE RESULT"))
    stats = report["provider_status"].get("lookup_stats", {})
    conf = report["provider_status"].get("configured", {})
    s.append(_table([["Provider", "Configured", "Lookup outcomes"]] +
                    [[p, "yes" if conf.get(p, conf.get(p.replace("_geolite2", "_city"), False)) else "no", ", ".join(f"{k}: {v}" for k, v in stats.get(p, {}).items()) or "-"]
                     for p in sorted(set(stats) | {"virustotal", "abuseipdb", "ipqualityscore", "maxmind_geolite2"})],
                    [45 * mm, 25 * mm, W - 70 * mm]))

    # ---- findings
    s.append(PageBreak())
    s.append(Paragraph("11. Findings and supporting evidence", H2))
    for f in sorted(report["findings"], key=lambda x: ["critical", "high", "medium", "low", "info"].index(x["severity"])):
        label = {"observed_fact": "OBSERVED FACT", "analytical_finding": "ANALYTICAL FINDING", "threat_intel": "THREAT INTELLIGENCE RESULT"}[f["finding_type"]]
        block = [_tag(label), Paragraph(f"<b>{escape(f['title'])}</b> &nbsp; [{f['severity'].upper()} / confidence {f['confidence']}] &nbsp; <font size=7>{escape(f['finding_id'])}</font>", BODY),
                 _p(f["description"], SMALL)]
        if f.get("why_it_matters"):
            block.append(_p("Why it matters: " + f["why_it_matters"], SMALL))
        for e in f.get("evidence", [])[:4]:
            block.append(_p(f"  evidence ({e['type']}) {e['label']}: {str(e['value'])[:220]} {('- ' + e['source']) if e.get('source') else ''}", SMALL))
        block.append(Spacer(1, 4))
        s.append(KeepTogether(block))

    # ---- correlation
    corr = report["correlation"]
    s.append(Paragraph("12. Correlation / threat graph", H2))
    s.append(_tag("ANALYTICAL FINDING"))
    m = corr.get("metrics", {})
    s.append(_p(f"{m.get('node_count')} nodes, {m.get('edge_count')} relationships; node types {m.get('node_types')}; pivot indicators: {', '.join(m.get('pivot_indicators', []))}."))
    rel_counts: dict[str, int] = {}
    for e in corr["edges"]:
        rel_counts[e["relation"]] = rel_counts.get(e["relation"], 0) + 1
    s.append(_p("Relationships: " + ", ".join(f"{k} x{v}" for k, v in sorted(rel_counts.items()))))
    for r in corr.get("related_analyses", []):
        s.append(_p(f"- Shares {len(r['shared_indicators'])} indicator(s) with earlier analysis {r['analysis_id']} ({r['risk_level']}): {r['subject']}", SMALL))

    # ---- timeline
    s.append(Paragraph("13. Investigation timeline", H2))
    s.append(_table([["Timestamp (UTC)", "Type", "Stage", "Event", "Status"]] +
                    [[t["timestamp"], t["kind"], t["stage"], t["event"] + (f" - {t['detail']}" if t.get("detail") else ""), t["status"]] for t in report["timeline"]],
                    [36 * mm, 20 * mm, 30 * mm, W - 104 * mm, 18 * mm]))

    # ---- limitations
    s.append(Paragraph("14. Limitations", H2))
    for lim in report["limitations"]:
        s.append(_p(f"- {lim}", SMALL))

    doc.build(s, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()
