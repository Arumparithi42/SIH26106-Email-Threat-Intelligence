"""Stage 5 - Correlation / threat graph (NetworkX).

Nodes use the stable indicator ids (email:, domain:, ip:, url:, file:, asn:, org:, ti:)
so the same indicator is the same node across analyses. Relationships follow the
agreed vocabulary (SENT_FROM, REPLY_TO, USES_DOMAIN, ROUTED_THROUGH, RESOLVES_TO,
CONTAINS_URL, HOSTED_BY, ASSOCIATED_WITH, CONTAINS_ATTACHMENT, MATCHES_THREAT_INTEL).
It also looks up earlier analyses that share indicators (cross-email correlation).
"""
from __future__ import annotations

import logging

import networkx as nx
from sqlalchemy import select

from app.database.db import session_scope
from app.database.models import Analysis, IndicatorRecord
from app.services.findings import ev, finding

log = logging.getLogger(__name__)
CORRELATABLE = ("ip:", "domain:", "url:", "file:", "email:")


class ThreatGraph:
    def __init__(self) -> None:
        self.g = nx.MultiDiGraph()

    def node(self, nid: str, ntype: str, label: str, **data) -> str:
        if nid in self.g:
            self.g.nodes[nid]["data"].update({k: v for k, v in data.items() if v is not None})
        else:
            self.g.add_node(nid, type=ntype, label=label, data={k: v for k, v in data.items() if v is not None})
        return nid

    def edge(self, src: str, dst: str, rel: str, **data) -> None:
        if src and dst and src in self.g and dst in self.g:
            if not any(d.get("relation") == rel for d in self.g.get_edge_data(src, dst, default={}).values()):
                self.g.add_edge(src, dst, relation=rel, data=data)

    def export(self) -> tuple[list[dict], list[dict]]:
        nodes = [{"id": n, "type": d["type"], "label": d["label"], "data": d["data"]} for n, d in self.g.nodes(data=True)]
        edges = [{"source": s, "target": t, "relation": d["relation"], "data": d.get("data", {})} for s, t, d in self.g.edges(data=True)]
        return nodes, edges


def build_graph(analysis_id: str, parsed: dict, header: dict, intel: dict, risk_flags: dict[str, str]) -> tuple[dict, list]:
    tg = ThreatGraph()
    h = parsed["headers"]
    msg = tg.node(f"message:{analysis_id}", "email", (h.get("subject") or "(no subject)")[:60], subject=h.get("subject"), date=h.get("date_iso"))

    def addr_node(a: dict | None, role: str) -> str | None:
        if not a or not a.get("address"):
            return None
        nid = tg.node(f"email:{a['address']}", "email_address", a["address"], display_name=a.get("display_name"), role=role)
        if a.get("domain"):
            from app.core.utils import registrable_domain
            dom = registrable_domain(a["domain"]) or a["domain"]
            tg.node(f"domain:{dom}", "domain", dom)
            tg.edge(nid, f"domain:{dom}", "USES_DOMAIN")
        return nid

    tg.edge(msg, addr_node(h.get("from"), "from"), "SENT_FROM")
    tg.edge(msg, addr_node(h.get("reply_to"), "reply_to"), "REPLY_TO")
    tg.edge(msg, addr_node(h.get("return_path"), "return_path"), "RETURN_PATH")
    for a in h.get("to") or []:
        tg.edge(msg, addr_node(a, "to"), "SENT_TO")

    for ip in intel["ip_intelligence"]:
        iid = tg.node(ip["id"], "ip", ip["ip"], roles=ip["roles"], country=ip["geolocation"].get("country_code") or ip["geolocation"].get("country"),
                      tor=ip["anonymization"]["tor"]["value"], vpn=ip["anonymization"]["vpn"]["value"], risk=risk_flags.get(ip["id"]))
        net = ip["network"]
        if net.get("asn"):
            aid = tg.node(f"asn:{net['asn']}", "asn", net["asn"], organization=net.get("organization"))
            tg.edge(iid, aid, "ASSOCIATED_WITH")
            if net.get("organization"):
                oid = tg.node(f"org:{net['organization']}", "organization", net["organization"])
                tg.edge(aid, oid, "ASSOCIATED_WITH")
        for pname, rep in ip["reputation"].items():
            if rep.get("verdict") in ("malicious", "suspicious"):
                tid = tg.node(f"ti:{pname}:{rep['verdict']}", "threat_intel", f"{pname}: {rep['verdict']}")
                tg.edge(iid, tid, "MATCHES_THREAT_INTEL", summary=rep.get("summary"))
    for hop in header.get("received_chain", []):
        if hop.get("ip"):
            tg.node(f"ip:{hop['ip']}", "ip", hop["ip"])
            tg.edge(msg, f"ip:{hop['ip']}", "ROUTED_THROUGH", hop=hop["hop"], server=hop.get("server"))

    for d in intel["domain_intelligence"]:
        did = tg.node(d["id"], "domain", d["domain"], roles=d["roles"], age_days=d["registration"].get("age_days"),
                      lookalike_of=d.get("lookalike_of"), risk=risk_flags.get(d["id"]))
        for ip in d["resolved_ips"][:5]:
            tg.node(f"ip:{ip}", "ip", ip)
            tg.edge(did, f"ip:{ip}", "RESOLVES_TO")
        for pname, rep in d["reputation"].items():
            if rep.get("verdict") in ("malicious", "suspicious"):
                tid = tg.node(f"ti:{pname}:{rep['verdict']}", "threat_intel", f"{pname}: {rep['verdict']}")
                tg.edge(did, tid, "MATCHES_THREAT_INTEL", summary=rep.get("summary"))

    for u in intel["url_analysis"]:
        uid = tg.node(u["id"], "url", u["url"][:60], characteristics=[c["code"] for c in u.get("characteristics", [])], risk=risk_flags.get(u["id"]))
        tg.edge(msg, uid, "CONTAINS_URL")
        if u.get("is_ip_based"):
            tg.node(f"ip:{u['hostname']}", "ip", u["hostname"])
            tg.edge(uid, f"ip:{u['hostname']}", "HOSTED_BY")
        elif u.get("domain"):
            tg.node(f"domain:{u['domain']}", "domain", u["domain"])
            tg.edge(uid, f"domain:{u['domain']}", "HOSTED_BY")
        for ip in u.get("resolved_ips", [])[:3]:
            tg.node(f"ip:{ip}", "ip", ip)
            tg.edge(f"domain:{u['domain']}", f"ip:{ip}", "RESOLVES_TO")
        for pname, rep in (u.get("reputation") or {}).items():
            if rep.get("verdict") in ("malicious", "suspicious"):
                tid = tg.node(f"ti:{pname}:{rep['verdict']}", "threat_intel", f"{pname}: {rep['verdict']}")
                tg.edge(uid, tid, "MATCHES_THREAT_INTEL", summary=rep.get("summary"))

    for att in parsed.get("attachments", []):
        fid = tg.node(f"file:{att['sha256']}", "attachment", att["filename"], sha256=att["sha256"], flags=[f["code"] for f in att["flags"]])
        tg.edge(msg, fid, "CONTAINS_ATTACHMENT")

    # ---- cross-analysis correlation (indicators seen in earlier emails)
    related, findings = [], []
    # the recipient's own infrastructure (mailbox domain, internal relays, private IPs) is in
    # every email they receive, so it must not count as "shared infrastructure"
    from app.core.utils import is_public_ip, registrable_domain
    recipients = (h.get("to") or []) + (h.get("cc") or [])
    recipient_orgs = {registrable_domain(a["domain"]) for a in recipients if a.get("domain")}
    excluded = {f"domain:{d}" for d in recipient_orgs} | {f"email:{a['address']}" for a in recipients}
    for hop in header.get("received_chain", []):
        if hop.get("ip") and (not is_public_ip(hop["ip"]) or registrable_domain(hop.get("hostname")) in recipient_orgs):
            excluded.add(f"ip:{hop['ip']}")
    excluded |= {n for n in tg.g.nodes if n.startswith("ip:") and not is_public_ip(n[3:])}
    ids = [n for n in tg.g.nodes if n.startswith(CORRELATABLE) and n not in excluded]
    try:
        with session_scope() as s:
            rows = s.execute(select(IndicatorRecord.indicator_id, IndicatorRecord.analysis_id, Analysis.subject, Analysis.risk_level, Analysis.created_at)
                             .join(Analysis, Analysis.analysis_id == IndicatorRecord.analysis_id)
                             .where(IndicatorRecord.indicator_id.in_(ids), IndicatorRecord.analysis_id != analysis_id)).all()
    except Exception as exc:  # noqa: BLE001
        log.warning("cross-analysis lookup failed: %s", exc)
        rows = []
    by_analysis: dict[str, dict] = {}
    for ind_id, aid, subject, level, created in rows:
        entry = by_analysis.setdefault(aid, {"analysis_id": aid, "subject": subject, "risk_level": level, "created_at": str(created), "shared_indicators": []})
        if ind_id not in entry["shared_indicators"]:
            entry["shared_indicators"].append(ind_id)
    for aid, entry in by_analysis.items():
        pid = tg.node(f"message:{aid}", "email", (entry["subject"] or aid)[:60], previous_analysis=True, risk=entry["risk_level"])
        for ind_id in entry["shared_indicators"]:
            tg.edge(ind_id, pid, "SEEN_IN")
        related.append(entry)
    risky = [r for r in related if r["risk_level"] in ("HIGH", "CRITICAL")]
    if risky:
        shared = sorted({i for r in risky for i in r["shared_indicators"] if not i.startswith("email:")})
        if shared:
            findings.append(finding(
                "F-CORR-SHARED-WITH-HIGH-RISK", category="correlation", severity="medium", confidence="medium",
                title=f"Shares infrastructure with {len(risky)} earlier high-risk analysis(es)",
                description="Shared indicators: " + ", ".join(shared[:8]),
                why="Re-use of the same IPs, domains or URLs across emails is typical of a campaign.",
                evidence=[ev("earlier analysis", {"analysis_id": r["analysis_id"], "subject": r["subject"], "risk": r["risk_level"]}, "local database", "analytical_finding") for r in risky[:5]],
                sources=["correlation_graph"], related=shared[:10], module="correlation"))

    # ---- infrastructure overlap inside this email
    sending = [ip for ip in intel["ip_intelligence"] if "sending_ip" in ip["roles"]]
    url_ips = {ip for u in intel["url_analysis"] for ip in u.get("resolved_ips", [])} | {u["hostname"] for u in intel["url_analysis"] if u.get("is_ip_based")}
    overlap = [ip["ip"] for ip in sending if ip["ip"] in url_ips]
    if overlap:
        findings.append(finding(
            "F-CORR-SENDER-HOSTS-LINKS", category="correlation", severity="low", confidence="medium",
            title="The sending server also hosts the linked website",
            description="IP(s) " + ", ".join(overlap) + " both sent the email and serve a linked URL.",
            why="Single-server phishing kits send mail and host the landing page together. Small legitimate senders can do the same.",
            sources=["correlation_graph"], related=[f"ip:{i}" for i in overlap], module="correlation"))

    und = nx.Graph(tg.g)
    centrality = nx.degree_centrality(und) if und.number_of_nodes() > 1 else {}
    pivots = [n for n, _ in sorted(centrality.items(), key=lambda kv: kv[1], reverse=True) if not n.startswith("message:")][:5]
    nodes, edges = tg.export()
    metrics = {
        "node_count": len(nodes), "edge_count": len(edges),
        "node_types": {t: sum(1 for n in nodes if n["type"] == t) for t in sorted({n["type"] for n in nodes})},
        "connected_components": nx.number_connected_components(und) if und.number_of_nodes() else 0,
        "pivot_indicators": pivots,
        "threat_intel_matches": sum(1 for e in edges if e["relation"] == "MATCHES_THREAT_INTEL"),
    }
    return {"nodes": nodes, "edges": edges, "metrics": metrics, "related_analyses": related}, findings
