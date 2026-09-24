"""Received-chain parser.

Received headers are prepended by each server, so in the file they appear
NEWEST first. We reverse them so hop 1 is the oldest (closest to the sender).
Only the newest hops (added by the recipient's own servers) are trustworthy;
older hops can be forged by the sender, so each hop carries a `trust` note.
"""
from __future__ import annotations

import re
from email.utils import parsedate_to_datetime

from app.core.utils import iso, is_public_ip, parse_ip, registrable_domain

_WS = re.compile(r"\s+")
_FROM = re.compile(r"^\s*from\s+(.*?)(?=\s+by\s|\s+with\s|\s+id\s|\s+for\s|;|$)", re.IGNORECASE | re.DOTALL)
_BY = re.compile(r"\bby\s+([^\s;()]+)", re.IGNORECASE)
_WITH = re.compile(r"\bwith\s+([^\s;()]+)", re.IGNORECASE)
_ID = re.compile(r"\bid\s+<?([^\s;>]+)", re.IGNORECASE)
_FOR = re.compile(r"\bfor\s+<?([^\s;>]+@[^\s;>]+)>?", re.IGNORECASE)
_BRACKET_IP = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]")
_BARE_IPV4 = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])")
_RDNS = re.compile(r"\(\s*([A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})\s*\[")

LARGE_DELAY_SECONDS = 3600
BACKWARDS_TOLERANCE_SECONDS = 60


def parse_received_header(value: str) -> dict:
    text = _WS.sub(" ", value).strip()
    head, _, date_part = text.rpartition(";") if ";" in text else (text, "", "")
    from_seg_m = _FROM.search(head)
    from_seg = from_seg_m.group(1).strip() if from_seg_m else ""
    ip = None
    for rx in (_BRACKET_IP, _BARE_IPV4):
        m = rx.search(from_seg)
        if m and parse_ip(m.group(1)):
            ip = m.group(1)
            break
    helo = from_seg.split()[0] if from_seg else None
    if helo and helo.startswith(("[", "(")):
        helo = None
    rdns_m = _RDNS.search(from_seg)
    by_m, with_m, id_m, for_m = _BY.search(head), _WITH.search(head), _ID.search(head), _FOR.search(head)
    ts = None
    if date_part.strip():
        try:
            ts = parsedate_to_datetime(date_part.strip())
        except (TypeError, ValueError):
            ts = None
    return {
        "from_helo": helo,
        "from_rdns": rdns_m.group(1) if rdns_m else None,
        "from_ip": ip,
        "by_hostname": by_m.group(1) if by_m else None,
        "protocol": with_m.group(1) if with_m else None,
        "smtp_id": id_m.group(1) if id_m else None,
        "for_address": for_m.group(1) if for_m else None,
        "timestamp_dt": ts,
        "raw": text,
    }


def build_received_chain(received_headers: list[str], date_header_iso: str | None) -> tuple[list[dict], list[dict]]:
    """Return (hops oldest->newest, anomalies)."""
    parsed = [parse_received_header(v) for v in received_headers]
    parsed.reverse()  # oldest first
    hops: list[dict] = []
    anomalies: list[dict] = []
    prev_ts = None
    n = len(parsed)
    for i, p in enumerate(parsed, 1):
        ts = p.pop("timestamp_dt")
        delta = None
        if ts is not None and prev_ts is not None:
            delta = int((ts - prev_ts).total_seconds())
            if delta < -BACKWARDS_TOLERANCE_SECONDS:
                anomalies.append({"code": "timestamp_backwards", "hop": i, "severity": "low",
                                  "description": f"Hop {i} timestamp is {abs(delta)} s earlier than hop {i - 1}",
                                  "interpretation": "Clock skew between servers or a forged/injected Received header; needs investigation."})
            elif delta > LARGE_DELAY_SECONDS:
                anomalies.append({"code": "large_delay", "hop": i, "severity": "info",
                                  "description": f"{delta // 60} min delay between hop {i - 1} and hop {i}",
                                  "interpretation": "Queueing, greylisting or retries are common causes; it is an anomaly, not proof of anything."})
        if ts is None:
            anomalies.append({"code": "missing_timestamp", "hop": i, "severity": "info",
                              "description": f"Hop {i} has no parsable timestamp", "interpretation": "Timing for this hop cannot be verified."})
        if p["from_helo"] and p["from_rdns"]:
            helo_dom, rdns_dom = registrable_domain(p["from_helo"]), registrable_domain(p["from_rdns"])
            if helo_dom and rdns_dom and helo_dom != rdns_dom:
                anomalies.append({"code": "helo_rdns_mismatch", "hop": i, "severity": "low",
                                  "description": f"Hop {i}: server introduced itself as '{p['from_helo']}' but its IP reverse-resolves to '{p['from_rdns']}'",
                                  "interpretation": "The HELO name is chosen by the connecting server and can be anything; a mismatch is worth checking."})
        ip = p["from_ip"]
        hops.append({
            "hop": i,
            **p,
            "ip": ip,
            "hostname": p["from_rdns"] or p["from_helo"],
            "server": p["by_hostname"],
            "ip_is_public": bool(ip) and is_public_ip(ip),
            "timestamp": iso(ts),
            "time_delta_seconds": delta,
            "trust": "recorded_by_final_receiver" if i == n else "reported_by_upstream_server_may_be_forged",
        })
        if ts is not None:
            prev_ts = ts

    if not hops:
        anomalies.append({"code": "no_received_headers", "hop": None, "severity": "low",
                          "description": "The email has no Received headers",
                          "interpretation": "Real delivered mail almost always has them; the file may have been crafted or exported without transport headers."})
    elif date_header_iso:
        first_ts = next((h["timestamp"] for h in hops if h["timestamp"]), None)
        if first_ts:
            from datetime import datetime
            d = datetime.fromisoformat(date_header_iso.replace("Z", "+00:00"))
            f = datetime.fromisoformat(first_ts.replace("Z", "+00:00"))
            gap = (f - d).total_seconds()
            if gap < -600:
                anomalies.append({"code": "date_after_first_hop", "hop": 1, "severity": "low",
                                  "description": f"Date header is {int(-gap // 60)} min after the first Received timestamp",
                                  "interpretation": "The sender's clock is wrong or the Date header was set manually."})
            elif gap > 86400:
                anomalies.append({"code": "date_much_older", "hop": 1, "severity": "info",
                                  "description": f"Date header is {int(gap // 3600)} h before the first Received timestamp",
                                  "interpretation": "Long-delayed or back-dated message; check against the sender's normal behaviour."})
    return hops, anomalies


def pick_sending_ip(hops: list[dict], auth_results_ip: str | None) -> dict:
    """Choose the IP that handed the message to the recipient's infrastructure (used for SPF)."""
    if auth_results_ip and is_public_ip(auth_results_ip):
        return {"ip": auth_results_ip, "method": "reported_by_receiver (Authentication-Results/Received-SPF client-ip)"}
    for hop in reversed(hops):  # newest -> oldest
        if hop["ip"] and hop["ip_is_public"]:
            return {"ip": hop["ip"], "method": f"received_chain (first public IP from newest hop, hop {hop['hop']})", "hop": hop["hop"], "helo": hop["from_helo"]}
    return {"ip": None, "method": "not_determined"}
