"""Thin DNS wrapper around dnspython.

All DNS lookups in the project go through `resolve()`, so tests can replace it
with a fake and the app degrades gracefully when no resolver is reachable.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field

import dns.exception
import dns.resolver

from app.core.config import get_settings

log = logging.getLogger(__name__)

_lock = threading.Lock()
_cache: dict[tuple[str, str], tuple[float, "DNSResult"]] = {}
_down_until = 0.0
_consecutive_failures = 0
_CACHE_SECONDS = 300
_OUTAGE_BACKOFF_SECONDS = 30
_FAILURES_BEFORE_BACKOFF = 3  # a single slow domain must not disable DNS for everything


@dataclass
class DNSResult:
    status: str  # success | nxdomain | no_answer | unavailable | error | disabled
    records: list[str] = field(default_factory=list)
    error: str | None = None


def _format(rdata, rtype: str) -> str:
    if rtype == "TXT":
        return b"".join(rdata.strings).decode("utf-8", "replace")
    if rtype == "MX":
        return f"{rdata.preference} {str(rdata.exchange).rstrip('.')}"
    return str(rdata).rstrip(".")


def resolve(name: str, rtype: str) -> DNSResult:
    """Resolve one record type. Never raises."""
    global _down_until, _consecutive_failures
    settings = get_settings()
    if not settings.enable_dns:
        return DNSResult("disabled", error="DNS lookups disabled by configuration")
    key = (name.lower().rstrip("."), rtype)
    now = time.monotonic()
    with _lock:
        hit = _cache.get(key)
        if hit and hit[0] > now:
            return hit[1]
        if _down_until > now:
            return DNSResult("unavailable", error="DNS resolver unreachable (backing off)")
    try:
        answer = dns.resolver.resolve(key[0], rtype, lifetime=settings.dns_timeout_seconds)
        result = DNSResult("success", [_format(r, rtype) for r in answer])
    except dns.resolver.NXDOMAIN:
        result = DNSResult("nxdomain", error="Domain does not exist (NXDOMAIN)")
    except dns.resolver.NoAnswer:
        result = DNSResult("no_answer")
    except (dns.resolver.NoNameservers, dns.exception.Timeout, dns.resolver.LifetimeTimeout) as exc:
        log.warning("DNS unavailable for %s %s: %s", key[0], rtype, exc.__class__.__name__)
        with _lock:
            _consecutive_failures += 1
            if _consecutive_failures >= _FAILURES_BEFORE_BACKOFF:
                _down_until = time.monotonic() + _OUTAGE_BACKOFF_SECONDS
        return DNSResult("unavailable", error=f"DNS query failed: {exc.__class__.__name__}")
    except Exception as exc:  # noqa: BLE001 - DNS must never break the analysis
        return DNSResult("error", error=f"{exc.__class__.__name__}: {exc}")
    with _lock:
        _consecutive_failures = 0
        _cache[key] = (now + _CACHE_SECONDS, result)
    return result


def reset_state() -> None:
    """Used by tests."""
    global _down_until, _consecutive_failures
    with _lock:
        _cache.clear()
        _down_until = 0.0
        _consecutive_failures = 0
