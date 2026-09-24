"""SPF, DKIM and DMARC.

Two views are reported for each mechanism:
- `independent_check`: our own check, done NOW with live DNS;
- `receiver_reported`: what the recipient's mail server recorded at delivery
  (Authentication-Results header), trusted only if it was added by the final
  receiving server.
`status` (the effective result) prefers a definitive independent result, and
falls back to the trusted receiver result when DNS can't answer (e.g. the
domain no longer exists). Where they disagree, that disagreement is reported.
"""
from __future__ import annotations

import logging
import re
import warnings

import dkim
import spf

from app.core import dns as dnsx
from app.core.config import get_settings
from app.core.utils import registrable_domain

log = logging.getLogger(__name__)
# dkimpy logs key-lookup failures at ERROR; we report them as a DKIM status instead
_dkim_log = logging.getLogger(__name__ + ".dkimpy")
_dkim_log.setLevel(logging.CRITICAL)

DEFINITIVE = {"pass", "fail", "softfail", "neutral"}
_TAG = re.compile(r"\b(spf|dkim|dmarc)=(\w+)", re.IGNORECASE)
_KV = re.compile(r"\b(header\.d|header\.i|header\.from|smtp\.mailfrom|client-ip|smtp\.remote-ip)=([^\s;()]+)", re.IGNORECASE)
_SPF_MAP = {"pass": "pass", "fail": "fail", "softfail": "softfail", "neutral": "neutral", "none": "none",
            "temperror": "error", "permerror": "error"}


# ---------------------------------------------------------------- receiver-reported
def parse_receiver_results(auth_results: list[str], received_spf: list[str], final_receiver: str | None) -> dict:
    out: dict = {"present": False, "trusted": False, "authserv_id": None, "spf": None, "dkim": None, "dmarc": None,
                 "client_ip": None, "smtp_mailfrom": None, "header_d": None, "raw": None}
    if auth_results:
        raw = re.sub(r"\s+", " ", auth_results[0]).strip()  # topmost = added last = by final receiver
        out.update(present=True, raw=raw, authserv_id=raw.split(";", 1)[0].strip().split()[0] if raw else None)
        for mech, res in _TAG.findall(raw):
            out[mech.lower()] = out[mech.lower()] or res.lower()
        for key, val in _KV.findall(raw):
            key = key.lower()
            if key in ("client-ip", "smtp.remote-ip"):
                out["client_ip"] = val
            elif key == "smtp.mailfrom":
                out["smtp_mailfrom"] = val.lower()
            elif key == "header.d":
                out["header_d"] = val.lower()
        a = registrable_domain(out["authserv_id"]) if out["authserv_id"] else None
        f = registrable_domain(final_receiver) if final_receiver else None
        out["trusted"] = bool(a and f and a == f)
    if received_spf:
        rs = re.sub(r"\s+", " ", received_spf[0]).strip()
        first = rs.split()[0].lower() if rs else None
        out["received_spf_raw"] = rs
        if not out["spf"] and first:
            out["spf"] = first
            out["present"] = True
        m = re.search(r"client-ip=([0-9A-Fa-f:.]+)", rs)
        if m and not out["client_ip"]:
            out["client_ip"] = m.group(1)
    return out


def _effective(independent: str, receiver: str | None, receiver_trusted: bool) -> tuple[str, str]:
    if independent in DEFINITIVE:
        return independent, "independent_check"
    if receiver and receiver_trusted:
        return receiver, "receiver_reported"
    return independent, "independent_check"


# ---------------------------------------------------------------- SPF
def spf_check(ip: str, sender: str, helo: str) -> tuple[str, str]:
    """Isolated so tests can replace it. Returns (result, explanation)."""
    if not get_settings().enable_dns:
        return "temperror", "DNS disabled by configuration"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)  # pyspf uses a deprecated dnspython alias
        return spf.check2(i=ip, s=sender, h=helo or "unknown", timeout=get_settings().dns_timeout_seconds + 2)


def check_spf(sending_ip: str | None, mail_from: str | None, from_domain: str | None, helo: str | None, receiver: dict) -> dict:
    domain = (mail_from.rsplit("@", 1)[-1] if mail_from and "@" in mail_from else None) or from_domain
    res = {"domain": domain, "ip": sending_ip, "mail_from": mail_from, "record": None}
    if not sending_ip or not domain:
        independent, evidence = "unknown", "No reliable sending IP or sender domain to evaluate SPF against"
    else:
        try:
            raw_result, explanation = spf_check(sending_ip, mail_from or f"postmaster@{domain}", helo or "")
            independent = _SPF_MAP.get(raw_result, "unknown")
            evidence = f"pyspf result '{raw_result}': {explanation}"
        except Exception as exc:  # noqa: BLE001
            independent, evidence = "error", f"SPF evaluation failed: {exc}"
        txt = dnsx.resolve(domain, "TXT")
        if txt.status == "success":
            res["record"] = next((r for r in txt.records if r.lower().startswith("v=spf1")), None)
    status, source = _effective(independent, receiver.get("spf"), receiver.get("trusted"))
    res.update(status=status, status_source=source, independent_check=independent, receiver_reported=receiver.get("spf"),
               evidence=evidence if source == "independent_check" else f"{evidence}. Receiving server recorded spf={receiver.get('spf')} at delivery.")
    res["disagreement"] = bool(independent in DEFINITIVE and receiver.get("spf") in DEFINITIVE and receiver.get("trusted") and independent != receiver.get("spf"))
    return res


# ---------------------------------------------------------------- DKIM
_DKIM_TAG = re.compile(r"(\w+)\s*=\s*([^;]*)")


def parse_dkim_signature(value: str) -> dict:
    tags = {k.lower(): re.sub(r"\s+", "", v) for k, v in _DKIM_TAG.findall(value)}
    return {"domain": tags.get("d", "").lower() or None, "selector": tags.get("s"), "algorithm": tags.get("a"),
            "signed_headers": tags.get("h"), "canonicalization": tags.get("c"), "body_hash": tags.get("bh")}


def verify_dkim_signatures(raw: bytes, signatures: list[str]) -> list[dict]:
    results = []
    for idx, sig in enumerate(signatures):
        meta = parse_dkim_signature(sig)
        state = {"dns": None}

        def dnsfunc(name, timeout=5):  # dkimpy callback
            qname = name.decode() if isinstance(name, bytes) else name
            r = dnsx.resolve(qname.rstrip("."), "TXT")
            state["dns"] = r.status
            return "".join(r.records).encode() if r.status == "success" else None

        try:
            ok = dkim.DKIM(raw, logger=_dkim_log).verify(idx=idx, dnsfunc=dnsfunc)
            if ok:
                status, evidence = "pass", "Signature verified with the published public key"
            elif state["dns"] in ("unavailable", "error", "disabled"):
                status, evidence = "error", f"Could not fetch public key (DNS {state['dns']}): temperror"
            elif state["dns"] in ("nxdomain", "no_answer"):
                status, evidence = "error", f"Public key {meta['selector']}._domainkey.{meta['domain']} not found in DNS: permerror"
            else:
                status, evidence = "fail", "Signature did not verify (message altered after signing or wrong key)"
        except dkim.ValidationError as exc:
            status, evidence = "fail", f"Validation failed: {exc}"
        except dkim.KeyFormatError as exc:
            if state["dns"] in ("unavailable", "error", "disabled"):
                status, evidence = "error", f"Could not fetch public key (DNS {state['dns']}): temperror"
            else:
                status, evidence = "error", f"Public key not found/invalid in DNS ({exc}): permerror"
        except dkim.DKIMException as exc:
            status, evidence = "error", f"DKIM error: {exc}"
        except Exception as exc:  # noqa: BLE001
            status, evidence = "error", f"Unexpected DKIM error: {exc.__class__.__name__}"
        results.append({**meta, "status": status, "evidence": evidence})
    return results


def check_dkim(raw: bytes, signatures: list[str], receiver: dict) -> dict:
    sigs = verify_dkim_signatures(raw, signatures) if signatures else []
    if not sigs:
        independent = "none"
    elif any(s["status"] == "pass" for s in sigs):
        independent = "pass"
    elif any(s["status"] == "fail" for s in sigs):
        independent = "fail"
    else:
        independent = "error"
    status, source = _effective(independent, receiver.get("dkim"), receiver.get("trusted"))
    evidence = "No DKIM-Signature header present" if not sigs else "; ".join(f"d={s['domain']} s={s['selector']}: {s['status']} ({s['evidence']})" for s in sigs)
    if source == "receiver_reported":
        evidence += f". Receiving server recorded dkim={receiver.get('dkim')} (header.d={receiver.get('header_d')}) at delivery."
    domain = next((s["domain"] for s in sigs if s["status"] == "pass"), None) or (sigs[0]["domain"] if sigs else None)
    if source == "receiver_reported" and receiver.get("header_d"):
        domain = receiver["header_d"]
    return {"status": status, "status_source": source, "independent_check": independent, "receiver_reported": receiver.get("dkim"),
            "domain": domain, "signatures": sigs, "evidence": evidence}


# ---------------------------------------------------------------- DMARC
def _fetch_dmarc(domain: str) -> tuple[str, str | None, str]:
    """Returns (dns_status, record, queried_name)."""
    for name in dict.fromkeys([f"_dmarc.{domain}", f"_dmarc.{registrable_domain(domain) or domain}"]):
        r = dnsx.resolve(name, "TXT")
        if r.status == "success":
            rec = next((x for x in r.records if x.lower().replace(" ", "").startswith("v=dmarc1")), None)
            if rec:
                return "success", rec, name
        elif r.status in ("unavailable", "error", "disabled"):
            return r.status, None, name
    return "not_found", None, f"_dmarc.{domain}"


def _aligned(a: str | None, b: str | None, mode: str) -> bool:
    if not a or not b:
        return False
    return a == b if mode == "s" else registrable_domain(a) == registrable_domain(b)


def check_dmarc(from_domain: str | None, spf_res: dict, dkim_res: dict, receiver: dict) -> dict:
    res = {"domain": from_domain, "record": None, "policy": None, "subdomain_policy": None, "pct": None,
           "adkim": "r", "aspf": "r", "spf_alignment": "unknown", "dkim_alignment": "unknown"}
    if not from_domain:
        res.update(status="unknown", independent_check="unknown", receiver_reported=receiver.get("dmarc"),
                   status_source="independent_check", evidence="No From domain")
        return res
    dns_status, record, qname = _fetch_dmarc(from_domain)
    tags = {}
    if record:
        tags = {k.strip().lower(): v.strip() for k, v in (p.split("=", 1) for p in record.split(";") if "=" in p)}
        res.update(record=record, policy=tags.get("p"), subdomain_policy=tags.get("sp"), pct=tags.get("pct", "100"),
                   adkim=tags.get("adkim", "r"), aspf=tags.get("aspf", "r"))

    spf_status = spf_res.get("status")
    spf_domain = spf_res.get("domain")
    if spf_status == "pass":
        res["spf_alignment"] = "pass" if _aligned(spf_domain, from_domain, res["aspf"]) else "fail"
    elif spf_status in ("fail", "softfail", "neutral", "none"):
        res["spf_alignment"] = "fail"
    passing_dkim = [s["domain"] for s in dkim_res.get("signatures", []) if s["status"] == "pass"]
    if dkim_res.get("status_source") == "receiver_reported" and dkim_res.get("status") == "pass" and dkim_res.get("domain"):
        passing_dkim.append(dkim_res["domain"])
    if passing_dkim:
        res["dkim_alignment"] = "pass" if any(_aligned(d, from_domain, res["adkim"]) for d in passing_dkim) else "fail"
    elif dkim_res.get("status") in ("fail", "none"):
        res["dkim_alignment"] = "fail" if dkim_res.get("status") == "fail" else "not_applicable"

    if dns_status in ("unavailable", "error", "disabled"):
        independent, evidence = "error", f"Could not query {qname} (DNS {dns_status})"
    elif not record:
        independent, evidence = "none", f"No DMARC record published at {qname}"
    elif "pass" in (res["spf_alignment"], res["dkim_alignment"]):
        independent, evidence = "pass", f"Aligned {'SPF' if res['spf_alignment'] == 'pass' else 'DKIM'} pass for {from_domain}; policy p={res['policy']}"
    elif res["spf_alignment"] == "unknown" and res["dkim_alignment"] in ("unknown", "not_applicable"):
        independent, evidence = "unknown", "SPF/DKIM results unavailable, alignment cannot be decided"
    else:
        independent, evidence = "fail", f"Neither SPF nor DKIM produced an aligned pass for {from_domain}; published policy p={res['policy']}"
    status, source = _effective(independent, receiver.get("dmarc"), receiver.get("trusted"))
    if source == "receiver_reported":
        evidence += f". Receiving server recorded dmarc={receiver.get('dmarc')} at delivery."
    res.update(status=status, status_source=source, independent_check=independent, receiver_reported=receiver.get("dmarc"), evidence=evidence)
    return res
