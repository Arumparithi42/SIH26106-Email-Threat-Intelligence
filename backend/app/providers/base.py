"""Common provider interface.

Every external source implements `Provider.fetch()` (one API call -> ProviderResult).
Everything shared lives once in `run_lookup()`:
  unsupported/private -> not configured -> backoff -> cache -> budget -> call
  (timeout + one retry on timeout/5xx) -> map errors -> cache store.
A provider problem therefore NEVER breaks the analysis; it becomes a status.
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select

from app.core.config import Settings
from app.core.utils import is_public_ip, iso, utcnow
from app.database.db import session_scope
from app.database.models import ProviderCache, ProviderState
from app.schemas.report import ProviderResult

log = logging.getLogger(__name__)


class ProviderFailure(Exception):
    """Raised by a provider for API-level failures (e.g. success=false in the body)."""

    def __init__(self, status: str, reason_code: str, message: str, backoff: bool = False):
        super().__init__(message)
        self.status, self.reason_code, self.message, self.backoff = status, reason_code, message, backoff


class Provider:
    name: str = "base"
    supported_types: set[str] = set()
    requires_key: bool = True
    cacheable: bool = True
    budget_limit_attr: str | None = None  # Settings attribute holding a per-analysis cap

    def __init__(self, settings: Settings):
        self.settings = settings

    def is_configured(self) -> bool:
        return True

    def cache_variant(self) -> str:
        return ""

    def ttl(self, result: ProviderResult) -> timedelta:
        hours = self.settings.cache_ttl_hours if result.status == "success" else self.settings.cache_ttl_unknown_hours
        return timedelta(hours=hours)

    def fetch(self, client: httpx.Client, indicator_type: str, indicator: str) -> ProviderResult:  # pragma: no cover
        raise NotImplementedError

    # helpers for subclasses
    def result(self, indicator_type: str, indicator: str, status: str, **kw) -> ProviderResult:
        return ProviderResult(provider=self.name, indicator=indicator, indicator_type=indicator_type, status=status,
                              retrieved_at=kw.pop("retrieved_at", iso(utcnow())), **kw)


class LookupContext:
    """Per-analysis state shared by all lookups: HTTP client, budgets, disabled providers."""

    def __init__(self, settings: Settings, client: httpx.Client | None = None):
        self.settings = settings
        self.client = client or httpx.Client(timeout=settings.http_timeout_seconds, follow_redirects=True,
                                             headers={"User-Agent": "SIH26106-EmailThreatIntel/1.0"})
        self._own_client = client is None
        self._lock = threading.Lock()
        self._used: dict[str, int] = {}
        self.disabled: dict[str, str] = {}  # provider -> reason (rate limited during this analysis)
        self.stats: dict[str, dict[str, int]] = {}

    def take_budget(self, provider: Provider) -> bool:
        if not provider.budget_limit_attr:
            return True
        limit = int(getattr(self.settings, provider.budget_limit_attr))
        with self._lock:
            used = self._used.get(provider.name, 0)
            if used >= limit:
                return False
            self._used[provider.name] = used + 1
            return True

    def record(self, r: ProviderResult) -> None:
        with self._lock:
            s = self.stats.setdefault(r.provider, {})
            s[r.status] = s.get(r.status, 0) + 1

    def close(self) -> None:
        if self._own_client:
            self.client.close()


# ---------------------------------------------------------------- cache + state
def _aware(dt: datetime | None) -> datetime | None:
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def cache_get(provider: str, itype: str, indicator: str, variant: str = "") -> ProviderResult | None:
    try:
        with session_scope() as s:
            row = s.execute(select(ProviderCache).where(
                ProviderCache.provider == provider, ProviderCache.indicator_type == itype,
                ProviderCache.indicator == indicator, ProviderCache.variant == variant)).scalar_one_or_none()
            if row and _aware(row.expires_at) > utcnow():
                r = ProviderResult(**row.response_json)
                r.cached = True
                return r
    except Exception as exc:  # noqa: BLE001 - cache problems must not break lookups
        log.warning("cache read failed: %s", exc)
    return None


def cache_put(r: ProviderResult, variant: str, ttl: timedelta) -> None:
    try:
        now = utcnow()
        with session_scope() as s:
            row = s.execute(select(ProviderCache).where(
                ProviderCache.provider == r.provider, ProviderCache.indicator_type == r.indicator_type,
                ProviderCache.indicator == r.indicator, ProviderCache.variant == variant)).scalar_one_or_none()
            payload = r.model_dump()
            payload["cached"] = False
            if row is None:
                s.add(ProviderCache(provider=r.provider, indicator_type=r.indicator_type, indicator=r.indicator, variant=variant,
                                    status=r.status, response_json=payload, retrieved_at=now, expires_at=now + ttl))
            else:
                row.status, row.response_json, row.retrieved_at, row.expires_at = r.status, payload, now, now + ttl
    except Exception as exc:  # noqa: BLE001
        log.warning("cache write failed: %s", exc)


def provider_blocked(provider: str) -> ProviderState | None:
    try:
        with session_scope() as s:
            st = s.get(ProviderState, provider)
            if st and st.blocked_until and _aware(st.blocked_until) > utcnow():
                return st
    except Exception as exc:  # noqa: BLE001
        log.warning("provider_state read failed: %s", exc)
    return None


def set_backoff(provider: str, hours: int, reason: str, message: str) -> None:
    try:
        now = utcnow()
        with session_scope() as s:
            st = s.get(ProviderState, provider) or ProviderState(provider=provider)
            st.blocked_until, st.reason_code, st.last_message, st.updated_at = now + timedelta(hours=hours), reason, message[:500], now
            s.merge(st)
    except Exception as exc:  # noqa: BLE001
        log.warning("provider_state write failed: %s", exc)


# ---------------------------------------------------------------- the one wrapper
def run_lookup(provider: Provider, itype: str, indicator: str, ctx: LookupContext) -> ProviderResult:
    r = _run(provider, itype, indicator, ctx)
    ctx.record(r)
    return r


def _run(provider: Provider, itype: str, indicator: str, ctx: LookupContext) -> ProviderResult:
    def skipped(reason: str, summary: str, status: str = "skipped") -> ProviderResult:
        return provider.result(itype, indicator, status, reason_code=reason, summary=summary, retrieved_at=None)

    if itype not in provider.supported_types:
        return skipped("unsupported_type", f"{provider.name} does not support {itype} lookups")
    if itype == "ip" and not is_public_ip(indicator):
        return skipped("private_ip", "Private/reserved IP address - not sent to external services")
    if not provider.is_configured():
        return skipped("no_api_key" if provider.requires_key else "not_configured", "Not configured")
    if provider.name in ctx.disabled:
        return skipped("rate_limited", f"Rate limited earlier in this analysis: {ctx.disabled[provider.name]}", "rate_limited")
    st = provider_blocked(provider.name)
    if st:
        return skipped("provider_backoff", f"Paused until {iso(_aware(st.blocked_until))} after: {st.last_message}", "rate_limited")
    variant = provider.cache_variant()
    if provider.cacheable:
        hit = cache_get(provider.name, itype, indicator, variant)
        if hit:
            return hit
    if not ctx.take_budget(provider):
        return skipped("budget_exceeded", "Per-analysis lookup budget used up (protects free-tier quota)")

    result: ProviderResult | None = None
    for attempt in (1, 2):
        try:
            result = provider.fetch(ctx.client, itype, indicator)
            break
        except ProviderFailure as pf:
            result = provider.result(itype, indicator, pf.status, reason_code=pf.reason_code, summary=pf.message, error=pf.message)
            if pf.status == "rate_limited":
                ctx.disabled[provider.name] = pf.message
                if pf.backoff:
                    set_backoff(provider.name, ctx.settings.provider_backoff_hours, pf.reason_code, pf.message)
            break
        except httpx.TimeoutException:
            result = provider.result(itype, indicator, "unavailable", reason_code="timeout", summary="Request timed out", error="timeout")
        except httpx.HTTPStatusError as exc:
            code = exc.response.status_code
            if code == 429:
                result = provider.result(itype, indicator, "rate_limited", reason_code="rate_limited", summary="HTTP 429 Too Many Requests", error="429")
                ctx.disabled[provider.name] = "HTTP 429"
                break
            if code in (401, 403):
                result = provider.result(itype, indicator, "error", reason_code="invalid_key", summary=f"HTTP {code}: API key rejected", error=str(code))
                break
            if code >= 500:
                result = provider.result(itype, indicator, "unavailable", reason_code="http_5xx", summary=f"Provider server error HTTP {code}", error=str(code))
            else:
                result = provider.result(itype, indicator, "error", reason_code="http_error", summary=f"HTTP {code}", error=str(code))
                break
        except httpx.TransportError as exc:
            result = provider.result(itype, indicator, "unavailable", reason_code="connection_error", summary=f"Connection failed: {exc.__class__.__name__}", error=exc.__class__.__name__)
            break
        except ValueError as exc:  # JSON decode / missing fields
            result = provider.result(itype, indicator, "error", reason_code="bad_response", summary=f"Unexpected response: {exc}", error="bad_response")
            break
        except Exception as exc:  # noqa: BLE001 - never crash the pipeline
            log.exception("provider %s failed", provider.name)
            result = provider.result(itype, indicator, "error", reason_code="provider_error", summary=f"{exc.__class__.__name__}", error=str(exc)[:200])
            break
        if attempt == 1:
            log.info("retrying %s for %s after %s", provider.name, itype, result.reason_code)

    if provider.cacheable and result.status in ("success", "unknown"):
        cache_put(result, variant, provider.ttl(result))
    return result
