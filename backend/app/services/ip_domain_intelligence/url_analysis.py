"""Passive URL analysis - structure only. URLs are never visited or downloaded."""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from app.core.utils import domain_label, levenshtein, parse_ip, registrable_domain

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rb.gy", "tiny.cc", "shorturl.at", "rebrand.ly", "buff.ly"}
RISKY_TLDS = {"zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "cf", "work", "support", "rest", "cam"}
PATH_WORDS = re.compile(r"login|log-in|signin|sign-in|verify|verification|account|update|secure|password|banking|kyc|confirm|wallet|invoice", re.IGNORECASE)

CHAR_INFO = {
    "ip_based_url": ("medium", "Link points to a raw IP address instead of a domain name"),
    "display_text_mismatch": ("high", "Visible link text shows a different domain than the real destination"),
    "punycode": ("medium", "Internationalised (punycode) domain, can imitate other domains with look-alike characters"),
    "at_sign_in_url": ("medium", "'@' in the URL hides the real host after it"),
    "lookalike_domain": ("high", "Domain is a near-copy of the sender's or a protected domain"),
    "brand_in_subdomain": ("medium", "A trusted brand name is used as a subdomain of an unrelated domain"),
    "url_shortener": ("low", "URL shortener hides the final destination"),
    "no_tls": ("low", "Plain HTTP link (no TLS)"),
    "credential_keywords": ("low", "Path contains login/verify/account style keywords"),
    "many_subdomains": ("low", "Unusually deep subdomain nesting"),
    "non_standard_port": ("low", "Link uses a non-standard port"),
    "risky_tld": ("low", "Top-level domain frequently abused in cheap throw-away registrations"),
    "very_long_url": ("info", "Very long URL"),
    "domain_differs_from_sender": ("info", "Link domain differs from the sender's domain (very common, context only)"),
}


def lookalike_of(domain: str | None, references: list[str]) -> str | None:
    """Return the reference domain this one imitates (edit distance 1-2 on the main label), if any."""
    if not domain:
        return None
    label = domain_label(domain)
    for ref in references:
        if not ref or registrable_domain(ref) == registrable_domain(domain):
            continue
        rl = domain_label(ref)
        if len(rl) >= 4 and 0 < levenshtein(label, rl) <= (1 if len(rl) < 6 else 2):
            return ref
        if len(rl) >= 4 and rl in label and label != rl:  # e.g. ntbank-secure-verify vs ntbank
            return ref
    return None


def analyze_url(entry: dict, sender_domain: str | None, references: list[str]) -> dict:
    url = entry["url"]
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        return {"url": url, "error": "unparsable URL", "characteristics": []}
    is_ip = bool(parse_ip(host))
    reg = None if is_ip else registrable_domain(host)
    chars: list[str] = []
    if is_ip:
        chars.append("ip_based_url")
    if parts.scheme == "http":
        chars.append("no_tls")
    if "xn--" in host:
        chars.append("punycode")
    if "@" in parts.netloc:
        chars.append("at_sign_in_url")
    if reg in SHORTENERS:
        chars.append("url_shortener")
    if host.count(".") >= 4:
        chars.append("many_subdomains")
    if port and port not in (80, 443):
        chars.append("non_standard_port")
    if reg and reg.rsplit(".", 1)[-1] in RISKY_TLDS:
        chars.append("risky_tld")
    if len(url) > 120:
        chars.append("very_long_url")
    if PATH_WORDS.search(parts.path + "?" + parts.query):
        chars.append("credential_keywords")
    look = lookalike_of(reg, references)
    if look:
        chars.append("lookalike_domain")
    sub = host[: -len(reg)] if reg and host.endswith(reg) else ""
    brand_hits = [r for r in references if r and domain_label(r) in sub and registrable_domain(r) != reg]
    if brand_hits:
        chars.append("brand_in_subdomain")
    display_mismatch = []
    for text in entry.get("display_texts", []):
        m = re.search(r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})", text.lower())
        if m and registrable_domain(m.group(1)) and registrable_domain(m.group(1)) != (reg or host):
            display_mismatch.append(text)
    if display_mismatch:
        chars.append("display_text_mismatch")
    if sender_domain and reg and registrable_domain(sender_domain) != reg:
        chars.append("domain_differs_from_sender")

    return {
        "url": url,
        "id": f"url:{url}",
        "scheme": parts.scheme,
        "hostname": host,
        "domain": reg,
        "port": port,
        "path": parts.path,
        "query": parts.query,
        "is_ip_based": is_ip,
        "ip": host if is_ip else None,
        "found_in": entry.get("sources", []),
        "display_texts": entry.get("display_texts", []),
        "display_text_mismatch": display_mismatch,
        "lookalike_of": look or (brand_hits[0] if brand_hits else None),
        "characteristics": [{"code": c, "severity": CHAR_INFO[c][0], "description": CHAR_INFO[c][1]} for c in chars],
        "visited": False,
    }
