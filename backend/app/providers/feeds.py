"""Keyless public feeds: Tor bulk exit list and OpenPhish community feed.

Each feed is downloaded at most once per CACHE_TTL_FEED_HOURS, stored in the
provider_cache table, and matched locally. A feed that can't be downloaded
makes its lookups 'unavailable' - it never breaks the analysis.
"""
from __future__ import annotations

import logging
import threading
import time
from datetime import timedelta

import httpx

from app.providers.base import Provider, ProviderFailure, cache_get, cache_put
from app.schemas.report import ProviderResult

log = logging.getLogger(__name__)
_lock = threading.Lock()
_memory: dict[str, tuple[float, set[str], str]] = {}  # feed -> (expires_monotonic, items, retrieved_at)
_failed: dict[str, tuple[float, str]] = {}  # feed -> (retry_after_monotonic, reason)
_FAIL_BACKOFF_SECONDS = 300


def _load_feed(name: str, url: str, client: httpx.Client, ttl_hours: int) -> tuple[set[str], str]:
    with _lock:
        mem = _memory.get(name)
        if mem and mem[0] > time.monotonic():
            return mem[1], mem[2]
        cached = cache_get(name, "feed", url)
        if cached and cached.status == "success":
            items = set(cached.data.get("items", []))
            _memory[name] = (time.monotonic() + 600, items, cached.retrieved_at)
            return items, cached.retrieved_at
        fail = _failed.get(name)
        if fail and fail[0] > time.monotonic():
            raise ProviderFailure("unavailable", "feed_unavailable", f"{name} feed download failed recently: {fail[1]}")
        try:
            resp = client.get(url)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            _failed[name] = (time.monotonic() + _FAIL_BACKOFF_SECONDS, exc.__class__.__name__)
            raise ProviderFailure("unavailable", "feed_unavailable", f"{name} feed download failed: {exc.__class__.__name__}") from exc
        items = {line.strip() for line in resp.text.splitlines() if line.strip() and not line.startswith("#")}
        if not items:
            raise ProviderFailure("unavailable", "bad_response", f"{name} feed was empty")
        r = ProviderResult(provider=name, indicator=url, indicator_type="feed", status="success", data={"items": sorted(items)})
        from app.core.utils import iso, utcnow
        r.retrieved_at = iso(utcnow())
        cache_put(r, "", timedelta(hours=ttl_hours))
        _memory[name] = (time.monotonic() + 600, items, r.retrieved_at)
        log.info("downloaded %s feed (%d entries)", name, len(items))
        return items, r.retrieved_at


def reset_feeds() -> None:
    with _lock:
        _memory.clear()
        _failed.clear()


class TorExitListProvider(Provider):
    name = "tor_exit_list"
    supported_types = {"ip"}
    requires_key = False
    cacheable = False
    FEED_URL = "https://check.torproject.org/torbulkexitlist"

    def is_configured(self) -> bool:
        return self.settings.enable_public_feeds

    def fetch(self, client: httpx.Client, indicator_type: str, indicator: str) -> ProviderResult:
        items, fetched = _load_feed(self.name, self.FEED_URL, client, self.settings.cache_ttl_feed_hours)
        listed = indicator in items
        return self.result(indicator_type, indicator, "success", verdict="unknown", data={"listed": listed, "feed_retrieved_at": fetched, "feed_size": len(items)},
                           summary="Listed as a current Tor exit node" if listed else "Not in the current Tor exit list")


class OpenPhishProvider(Provider):
    name = "openphish"
    supported_types = {"url"}
    requires_key = False
    cacheable = False
    FEED_URL = "https://openphish.com/feed.txt"

    def is_configured(self) -> bool:
        return self.settings.enable_public_feeds

    def fetch(self, client: httpx.Client, indicator_type: str, indicator: str) -> ProviderResult:
        items, fetched = _load_feed(self.name, self.FEED_URL, client, self.settings.cache_ttl_feed_hours)
        norm = indicator.rstrip("/")
        listed = indicator in items or norm in items or norm + "/" in items
        return self.result(indicator_type, indicator, "success", verdict="malicious" if listed else "no_detections",
                           data={"listed": listed, "feed_retrieved_at": fetched, "feed_size": len(items)},
                           summary="Exact match in OpenPhish community feed" if listed else "Not in current OpenPhish feed (not proof of safety)")


class SafeBrowsingProvider(Provider):
    """Google Safe Browsing Lookup API v4 (optional)."""

    name = "google_safe_browsing"
    supported_types = {"url"}
    URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    def is_configured(self) -> bool:
        return bool(self.settings.google_safe_browsing_api_key)

    def fetch(self, client: httpx.Client, indicator_type: str, indicator: str) -> ProviderResult:
        body = {
            "client": {"clientId": "sih26106-email-intel", "clientVersion": "1.0"},
            "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                           "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": indicator}]},
        }
        resp = client.post(self.URL, params={"key": self.settings.google_safe_browsing_api_key}, json=body)
        resp.raise_for_status()
        matches = resp.json().get("matches", [])
        types = sorted({m.get("threatType") for m in matches})
        return self.result(indicator_type, indicator, "success", verdict="malicious" if matches else "no_detections",
                           data={"threat_types": types}, summary=("Listed: " + ", ".join(types)) if matches else "No Safe Browsing match (not proof of safety)")
