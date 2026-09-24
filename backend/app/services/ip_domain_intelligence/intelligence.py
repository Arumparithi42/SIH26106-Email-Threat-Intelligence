"""Stage 4 - IP & Domain Intelligence (+ URL reputation).

Consumes the IndicatorSet from Module 3 and produces per-IP, per-domain and
per-URL intelligence. Each fact keeps its source; missing data stays 'unknown'.
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

from app.core import dns as dnsx
from app.core.config import Settings
from app.core.utils import is_public_ip, is_reserved_domain, registrable_domain, sha256_hex
from app.providers.base import LookupContext, run_lookup
from app.providers.registry import build_providers
from app.schemas.report import ProviderResult
from app.services.findings import ev, finding
from app.services.ip_domain_intelligence.indicators import IndicatorSet
from app.services.ip_domain_intelligence.url_analysis import CHAR_INFO, analyze_url, lookalike_of

log = logging.getLogger(__name__)

IP_PROVIDER_ROLES = {
    "maxmind_geolite2": None,  # None = every public IP
    "tor_exit_list": None,
    "abuseipdb": {"sending_ip", "relay_ip", "url_ip", "originating_client_ip"},
    "ipqualityscore": {"sending_ip", "url_ip", "originating_client_ip"},
    "virustotal": {"sending_ip", "url_ip"},
}
DOMAIN_VT_ROLES = {"from_domain", "reply_to_domain", "return_path_domain", "url_domain"}
IMPORTANT_DOMAIN_ROLES = {"from_domain", "reply_to_domain", "return_path_domain", "url_domain", "sender_domain"}
NEW_DOMAIN_DAYS = 30
DNS_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]


# ---------------------------------------------------------------- DNS
def dns_profile(domain: str) -> dict:
    records, statuses = {}, {}
    for rtype in DNS_TYPES:
        r = dnsx.resolve(domain, rtype)
        statuses[rtype] = r.status
        records[rtype.lower()] = r.records
        if r.status in ("nxdomain", "unavailable", "disabled"):
            break  # no point asking more
    st = set(statuses.values())
    overall = ("nxdomain" if "nxdomain" in st else "unavailable" if st & {"unavailable", "disabled"} and "success" not in st
               else "success" if "success" in st else "no_records")
    txt = records.get("txt", [])
    dmarc = dnsx.resolve(f"_dmarc.{domain}", "TXT") if overall == "success" else None
    return {
        "status": overall, "query_status": statuses,
        "a": records.get("a", []), "aaaa": records.get("aaaa", []), "mx": records.get("mx", []), "ns": records.get("ns", []),
        "cname": records.get("cname", []), "txt": txt,
        "spf": next((t for t in txt if t.lower().startswith("v=spf1")), None),
        "dmarc": next((t for t in (dmarc.records if dmarc and dmarc.status == "success" else []) if t.lower().startswith("v=dmarc1")), None),
    }


# ---------------------------------------------------------------- signals
def _signal(evidence: list[tuple[str, str, object]]) -> dict:
    ev_list = [{"source": s, "field": f, "value": v} for s, f, v in evidence]
    answered = [v for _, _, v in evidence if isinstance(v, bool)]
    value = "detected" if any(answered) else "not_detected" if answered else "unknown"
    return {"value": value, "evidence": ev_list}


def _ok(r: ProviderResult | None) -> dict:
    return r.data if r and r.status == "success" else {}


def assemble_ip(ip: dict, results: dict[str, ProviderResult]) -> dict:
    mm, ipqs, abuse, vt, tor = (_ok(results.get(k)) for k in ("maxmind_geolite2", "ipqualityscore", "abuseipdb", "virustotal", "tor_exit_list"))
    if mm.get("asn") or mm.get("as_org"):
        network = {"asn": f"AS{mm['asn']}" if mm.get("asn") else None, "organization": mm.get("as_org"), "isp": ipqs.get("ISP") or abuse.get("isp"), "source": "maxmind_geolite2"}
    elif ipqs:
        network = {"asn": f"AS{ipqs['ASN']}" if ipqs.get("ASN") else None, "organization": ipqs.get("organization"), "isp": ipqs.get("ISP"), "source": "ipqualityscore"}
    elif vt.get("asn") or vt.get("as_owner"):
        network = {"asn": f"AS{vt['asn']}" if vt.get("asn") else None, "organization": vt.get("as_owner"), "isp": None, "source": "virustotal"}
    elif abuse:
        network = {"asn": None, "organization": None, "isp": abuse.get("isp"), "source": "abuseipdb"}
    else:
        network = {"asn": None, "organization": None, "isp": None, "source": None}
    if mm.get("latitude") is not None or mm.get("country"):
        geo = {k: mm.get(k) for k in ("country", "country_code", "region", "city", "latitude", "longitude", "accuracy_radius_km")}
        geo["source"] = "maxmind_geolite2"
    else:
        cc = abuse.get("countryCode") or vt.get("country") or ipqs.get("country_code")
        geo = {"country": None, "country_code": cc, "region": None, "city": None, "latitude": None, "longitude": None,
               "accuracy_radius_km": None, "source": ("country only: " + ("abuseipdb" if abuse.get("countryCode") else "virustotal" if vt.get("country") else "ipqualityscore")) if cc else None}
    geo["note"] = "Approximate location of network infrastructure, not of a person."

    def f(src: dict, name: str, field: str):
        return [(name, field, src.get(field))] if src and field in src else []

    hosting_ev = []
    if ipqs.get("connection_type"):
        hosting_ev.append(("ipqualityscore", "connection_type", ipqs["connection_type"] == "Data Center"))
    if abuse.get("usageType"):
        hosting_ev.append(("abuseipdb", "usageType", any(w in abuse["usageType"] for w in ("Data Center", "Hosting"))))
    anonymization = {
        "vpn": _signal(f(ipqs, "ipqualityscore", "vpn") + f(ipqs, "ipqualityscore", "active_vpn")),
        "proxy": _signal(f(ipqs, "ipqualityscore", "proxy")),
        "tor": _signal(f(tor, "tor_exit_list", "listed") + f(ipqs, "ipqualityscore", "tor") + f(ipqs, "ipqualityscore", "active_tor") + f(abuse, "abuseipdb", "isTor")),
        "hosting": _signal(hosting_ev),
        "active_vpn": ipqs.get("active_vpn") if ipqs else None,
        "active_tor": ipqs.get("active_tor") if ipqs else None,
        "connection_type": {"value": ipqs.get("connection_type"), "source": "ipqualityscore" if ipqs.get("connection_type") else None},
        "note": "VPN/proxy/Tor are indicators of anonymisation, not proof of malicious intent.",
    }
    return {
        "ip": ip["value"], "id": ip["id"], "roles": ip["roles"], "is_public": ip.get("is_public", True),
        "network": network, "geolocation": geo, "anonymization": anonymization,
        "reputation": {k: results[k].model_dump() for k in ("abuseipdb", "virustotal", "ipqualityscore") if k in results},
        "providers": [r.model_dump() for r in results.values()],
    }


# ---------------------------------------------------------------- main entry
def gather_intelligence(ind: IndicatorSet, parsed: dict, settings: Settings, ctx: LookupContext | None = None) -> dict:
    providers = build_providers(settings)
    own_ctx = ctx is None
    ctx = ctx or LookupContext(settings)
    sender_domain = ((parsed["headers"].get("from") or {}).get("domain"))
    protected = settings.protected_domain_list
    # the sender's own domain is a useful reference only when it is not itself a look-alike
    sender_ref = [sender_domain] if sender_domain and not lookalike_of(sender_domain, protected) else []
    references = list(dict.fromkeys([d for d in protected + sender_ref if d]))
    protected_regs = {registrable_domain(d) for d in protected}
    try:
        # 1) passive URL structure analysis
        urls = [analyze_url(u, sender_domain, references) for u in parsed.get("urls", [])]

        # 2) DNS for every registrable domain (+ URL hostnames) in parallel
        domain_names = list(ind.domains.keys())
        url_hosts = sorted({u["hostname"] for u in urls if u.get("hostname") and not u.get("is_ip_based")})
        with ThreadPoolExecutor(max_workers=8) as pool:
            dns_map = dict(zip(domain_names, pool.map(dns_profile, domain_names)))
            host_a = dict(zip(url_hosts, pool.map(lambda h: dnsx.resolve(h, "A"), url_hosts)))
        for host, r in host_a.items():
            if r.status == "success":
                for ip in r.records:
                    ind.ip(ip, "url_host_ip")
        for d, prof in dns_map.items():
            if "url_domain" in ind.domains[d]["roles"] or "from_domain" in ind.domains[d]["roles"]:
                for ip in prof["a"][:3]:
                    ind.ip(ip, "domain_resolved_ip")

        # 3) provider tasks, highest priority first (budgets are consumed in order)
        tasks: list[tuple[str, str, str]] = []
        ips_sorted = sorted(ind.ips.values(), key=lambda x: (0 if "sending_ip" in x["roles"] else 1 if "url_ip" in x["roles"] else 2))
        for ip in ips_sorted:
            if not is_public_ip(ip["value"]):
                continue
            for pname, roles in IP_PROVIDER_ROLES.items():
                if roles is None or roles & set(ip["roles"]):
                    tasks.append((pname, "ip", ip["value"]))
        for u in urls:
            for pname in ("openphish", "google_safe_browsing", "virustotal"):
                tasks.append((pname, "url", u["url"]))
        for d, item in ind.domains.items():
            tasks.append(("rdap", "domain", d))
            if DOMAIN_VT_ROLES & set(item["roles"]) and not is_reserved_domain(d):
                tasks.append(("virustotal", "domain", d))

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [(t, pool.submit(run_lookup, providers[t[0]], t[1], t[2], ctx)) for t in tasks]
            results: dict[tuple[str, str], dict[str, ProviderResult]] = {}
            for (pname, itype, value), fut in futures:
                results.setdefault((itype, value), {})[pname] = fut.result()

        # 4) assemble
        ip_intel = [assemble_ip(ip, results.get(("ip", ip["value"]), {})) for ip in ips_sorted]
        domain_intel = []
        for d, item in ind.domains.items():
            res = results.get(("domain", d), {})
            rdap = res.get("rdap")
            prof = dns_map.get(d, {})
            domain_intel.append({
                "domain": d, "id": item["id"], "roles": item["roles"], "hostnames": item.get("hostnames", []),
                "reserved_tld": is_reserved_domain(d),
                "dns": prof, "resolved_ips": prof.get("a", []) + prof.get("aaaa", []),
                "registration": {"status": rdap.status if rdap else "skipped", "source": "rdap", **(rdap.data if rdap and rdap.status == "success" else {}),
                                 "summary": rdap.summary if rdap else "Not queried"},
                "lookalike_of": None if d in protected_regs else lookalike_of(d, references),
                "reputation": {k: v.model_dump() for k, v in res.items() if k == "virustotal"},
                "providers": [v.model_dump() for v in res.values()],
            })
        for u in urls:
            res = results.get(("url", u["url"]), {})
            u["reputation"] = {k: v.model_dump() for k, v in res.items()}
            host_r = host_a.get(u["hostname"])
            u["resolved_ips"] = host_r.records if host_r and host_r.status == "success" else []
            u["dns_status"] = host_r.status if host_r else ("not_applicable" if u.get("is_ip_based") else "not_queried")
        findings = build_intel_findings(ip_intel, domain_intel, urls)
        return {"ip_intelligence": ip_intel, "domain_intelligence": domain_intel, "url_analysis": urls,
                "findings": findings, "provider_stats": ctx.stats}
    finally:
        if own_ctx:
            ctx.close()


# ---------------------------------------------------------------- findings
def _ti_findings(indicator_id: str, label: str, reps: dict[str, dict]) -> list:
    bad = {k: v for k, v in reps.items() if v.get("status") == "success" and v.get("verdict") in ("malicious", "suspicious")}
    if not bad:
        return []
    malicious = [k for k, v in bad.items() if v["verdict"] == "malicious"]
    sev = "high" if malicious else "medium"
    conf = "high" if len(bad) >= 2 else "medium"
    return [finding(
        f"F-TI-{indicator_id.split(':', 1)[0].upper()}-{sha256_hex(indicator_id.encode())[:8]}",
        category="threat_intel", severity=sev, confidence=conf, finding_type="threat_intel",
        title=f"Threat intelligence flags {label}",
        description="; ".join(f"{k}: {v['verdict']} ({v.get('summary')})" for k, v in bad.items()),
        why="Independent threat-intelligence sources have associated this indicator with malicious activity. Coverage is incomplete and results can be stale.",
        evidence=[ev(k, v.get("summary"), k, "threat_intel") for k, v in bad.items()],
        sources=list(bad), related=[indicator_id], module="ip_domain_intelligence")]


def build_intel_findings(ip_intel: list[dict], domain_intel: list[dict], urls: list[dict]) -> list:
    out = []
    for ip in ip_intel:
        roles, iid = set(ip["roles"]), ip["id"]
        out += _ti_findings(iid, f"IP {ip['ip']} ({', '.join(ip['roles'])})", ip["reputation"])
        an = ip["anonymization"]
        key_ip = bool(roles & {"sending_ip", "originating_client_ip"})
        if key_ip and an["tor"]["value"] == "detected":
            out.append(finding(f"F-IP-TOR-{ip['ip']}", category="ip", severity="medium", confidence="high", finding_type="threat_intel",
                               title=f"Sending IP {ip['ip']} is a Tor exit node",
                               description="Tor exit list / IPQS report this IP as Tor.",
                               why="Tor hides the real origin of the sender. Tor is also used legitimately for privacy, so this is context, not proof.",
                               evidence=[ev(e["source"], f"{e['field']}={e['value']}", e["source"], "threat_intel") for e in an["tor"]["evidence"]],
                               sources=[e["source"] for e in an["tor"]["evidence"]], related=[iid], module="ip_domain_intelligence"))
        if key_ip and (an["vpn"]["value"] == "detected" or an["proxy"]["value"] == "detected"):
            dc = an["hosting"]["value"] == "detected"
            out.append(finding(f"F-IP-VPN-PROXY-{ip['ip']}", category="ip", severity="low", confidence="low" if dc else "medium", finding_type="threat_intel",
                               title=f"Sending IP {ip['ip']} flagged as VPN/proxy by IPQS",
                               description=f"vpn={an['vpn']['value']}, proxy={an['proxy']['value']}, connection_type={an['connection_type']['value']}.",
                               why="Anonymising infrastructure can hide the sender. IPQS also marks ordinary data-center mail servers as VPN, so this is weak evidence on its own.",
                               evidence=[ev(e["source"], f"{e['field']}={e['value']}", e["source"], "threat_intel") for e in an["vpn"]["evidence"] + an["proxy"]["evidence"]],
                               sources=["ipqualityscore"], related=[iid], module="ip_domain_intelligence"))
        ipqs = ip["reputation"].get("ipqualityscore") or {}
        if ipqs.get("status") == "success" and (ipqs.get("data") or {}).get("recent_abuse") is True:
            out.append(finding(f"F-IP-RECENT-ABUSE-{ip['ip']}", category="threat_intel", severity="medium", confidence="medium", finding_type="threat_intel",
                               title=f"IPQS reports recent abuse from {ip['ip']}",
                               description="IPQS recent_abuse=true (verified abuse across its network in the past days).",
                               why="Recent abusive behaviour from the same IP raises the likelihood this delivery is part of it.",
                               sources=["ipqualityscore"], related=[iid], module="ip_domain_intelligence"))
        if "url_ip" in roles and any(an[k]["value"] == "detected" for k in ("vpn", "proxy", "tor")):
            out.append(finding(f"F-URL-IP-ANONYMIZED-{ip['ip']}", category="url", severity="medium", confidence="medium", finding_type="threat_intel",
                               title=f"Link points to anonymised IP {ip['ip']}",
                               description="A URL in the email uses an IP flagged as VPN/proxy/Tor.",
                               why="Links to raw, anonymised IPs are rarely used by legitimate organisations.",
                               sources=["ipqualityscore", "tor_exit_list"], related=[iid], module="ip_domain_intelligence"))

    for d in domain_intel:
        roles, did = set(d["roles"]), d["id"]
        out += _ti_findings(did, f"domain {d['domain']}", d["reputation"])
        reg = d["registration"]
        important = roles & IMPORTANT_DOMAIN_ROLES
        if reg.get("age_days") is not None and reg["age_days"] < NEW_DOMAIN_DAYS and important:
            out.append(finding(f"F-DOM-NEW-{d['domain']}", category="domain", severity="medium", confidence="medium", finding_type="observed_fact",
                               title=f"Domain {d['domain']} was registered {reg['age_days']} days ago",
                               description=f"RDAP creation date {reg.get('created')}; roles: {', '.join(sorted(roles))}.",
                               why="Phishing domains are often registered shortly before use and have no reputation history yet. Many new domains are legitimate.",
                               evidence=[ev("created", reg.get("created"), "rdap")], sources=["rdap"], related=[did], module="ip_domain_intelligence"))
        if d["dns"].get("status") == "nxdomain" and important and not d["reserved_tld"]:
            out.append(finding(f"F-DOM-NXDOMAIN-{d['domain']}", category="domain", severity="medium" if roles & {"reply_to_domain", "from_domain"} else "low",
                               confidence="medium", finding_type="observed_fact",
                               title=f"Domain {d['domain']} does not exist in DNS (NXDOMAIN)",
                               description=f"Roles: {', '.join(sorted(roles))}.",
                               why="A sender/reply domain that does not resolve cannot be a normally operated mail domain (it may have been taken down after abuse).",
                               sources=["dns"], related=[did], module="ip_domain_intelligence"))
        if d["dns"].get("status") == "success" and "from_domain" in roles and not d["dns"]["mx"] and not d["dns"]["a"]:
            out.append(finding(f"F-DOM-NOMX-{d['domain']}", category="domain", severity="low", confidence="medium", finding_type="observed_fact",
                               title=f"Sender domain {d['domain']} has no MX or A record",
                               description="The domain cannot receive email.", why="Real organisations normally receive mail at the domain they send from.",
                               sources=["dns"], related=[did], module="ip_domain_intelligence"))

    looks = [d for d in domain_intel if d.get("lookalike_of") and set(d["roles"]) & IMPORTANT_DOMAIN_ROLES]
    if looks:
        out.append(finding("F-DOM-LOOKALIKE", category="domain", severity="high", confidence="medium", finding_type="analytical_finding",
                           title=f"{len(looks)} look-alike domain(s): " + ", ".join(d["domain"] for d in looks[:4]),
                           description="; ".join(f"{d['domain']} ({', '.join(d['roles'])}) resembles {d['lookalike_of']}" for d in looks),
                           why="Typosquatted / brand-containing domains trick readers into trusting a sender or link. Similarity alone does not prove malice.",
                           evidence=[ev(d["domain"], f"resembles {d['lookalike_of']}", "edit distance / brand containment", "analytical_finding") for d in looks],
                           sources=["lookalike_check"], related=[d["id"] for d in looks], module="ip_domain_intelligence"))

    agg: dict[str, list[dict]] = {}
    for u in urls:
        for c in u.get("characteristics", []):
            agg.setdefault(c["code"], []).append(u)
        out += _ti_findings(u["id"], f"URL {u['url'][:80]}", u.get("reputation", {}))
        listed = [k for k, v in (u.get("reputation") or {}).items() if k in ("openphish", "google_safe_browsing") and v.get("verdict") == "malicious"]
        if listed:
            out[-1].severity = "critical"  # exact listing in a phishing/malware blocklist
    for code, us in agg.items():
        sev, text = CHAR_INFO[code]
        if sev == "info" or code == "lookalike_domain":  # look-alikes are reported once, as a domain finding
            continue
        out.append(finding(f"F-URL-{code.upper().replace('_', '-')}", category="url", severity=sev,
                           confidence="high" if code in ("display_text_mismatch", "ip_based_url", "at_sign_in_url") else "medium",
                           title=text, description=f"{len(us)} URL(s): " + ", ".join(x["url"][:90] for x in us[:5]),
                           why="Structural URL trick commonly used to disguise a malicious destination; judged together with other evidence.",
                           evidence=[ev("url", x["url"], "email body") for x in us[:5]] + [ev("display text", t, "HTML anchor") for x in us for t in x.get("display_text_mismatch", [])][:3],
                           sources=["url_analysis"], related=[x["id"] for x in us], module="ip_domain_intelligence",
                           finding_type="observed_fact" if code in ("ip_based_url", "no_tls", "display_text_mismatch") else "analytical_finding"))
    return out
