"""Small shared helpers: time, hashing, IP classification, registrable domains."""
from __future__ import annotations

import hashlib
import ipaddress
from datetime import datetime, timezone
from functools import lru_cache

import tldextract

# offline extractor: uses the Public Suffix List snapshot bundled with tldextract,
# never downloads anything at runtime.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

RESERVED_TLDS = {"example", "test", "invalid", "localhost", "local"}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return None


def is_public_ip(value: str) -> bool:
    ip = parse_ip(value)
    return bool(ip) and ip.is_global


@lru_cache(maxsize=4096)
def registrable_domain(hostname: str | None) -> str | None:
    """'mail.evil.co.in' -> 'evil.co.in'. Returns None for IPs / empty input."""
    if not hostname:
        return None
    host = hostname.strip().strip(".").lower()
    if not host or parse_ip(host):
        return None
    ext = _EXTRACT(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    # unknown suffix (e.g. reserved '.example'): use last two labels
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def is_reserved_domain(domain: str | None) -> bool:
    return bool(domain) and domain.rsplit(".", 1)[-1].lower() in RESERVED_TLDS


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def domain_label(domain: str) -> str:
    """'ntbank.example' -> 'ntbank' (the part people recognise)."""
    ext = _EXTRACT(domain)
    if ext.domain and ext.suffix:
        return ext.domain
    parts = domain.lower().strip(".").split(".")  # unknown suffix, e.g. reserved '.example'
    return parts[-2] if len(parts) >= 2 else parts[0]
