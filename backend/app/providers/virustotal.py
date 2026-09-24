"""VirusTotal API v3 - multi-vendor reputation for IPs, domains and URLs.

URLs are looked up by their VT identifier (base64url of the URL); we never
submit URLs for scanning and never visit them.
"""
from __future__ import annotations

import base64

import httpx

from app.providers.base import Provider, ProviderFailure
from app.schemas.report import ProviderResult

BASE = "https://www.virustotal.com/api/v3"
PATHS = {"ip": "ip_addresses", "domain": "domains", "url": "urls"}


def url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


class VirusTotalProvider(Provider):
    name = "virustotal"
    supported_types = {"ip", "domain", "url"}
    budget_limit_attr = "vt_max_lookups_per_analysis"

    def is_configured(self) -> bool:
        return bool(self.settings.virustotal_api_key)

    def fetch(self, client: httpx.Client, indicator_type: str, indicator: str) -> ProviderResult:
        ident = url_id(indicator) if indicator_type == "url" else indicator
        resp = client.get(f"{BASE}/{PATHS[indicator_type]}/{ident}", headers={"x-apikey": self.settings.virustotal_api_key})
        if resp.status_code == 404:
            return self.result(indicator_type, indicator, "unknown", summary="Not in VirusTotal dataset (unknown, not 'safe')")
        if resp.status_code == 429:
            code = ""
            try:
                code = resp.json().get("error", {}).get("code", "")
            except ValueError:
                pass
            if code == "QuotaExceededError":
                raise ProviderFailure("rate_limited", "quota_exhausted", "VirusTotal quota exceeded", backoff=True)
            raise ProviderFailure("rate_limited", "rate_limited", "VirusTotal rate limit (HTTP 429)")
        resp.raise_for_status()
        attrs = resp.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats") or {}
        mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
        verdict = "malicious" if mal >= 3 else "suspicious" if (mal or sus) else "no_detections"
        flagged_by = sorted(k for k, v in (attrs.get("last_analysis_results") or {}).items() if v.get("category") in ("malicious", "suspicious"))[:10]
        data = {
            "last_analysis_stats": stats, "reputation": attrs.get("reputation"), "flagged_by": flagged_by,
            "last_analysis_date": attrs.get("last_analysis_date"), "categories": attrs.get("categories"),
            "asn": attrs.get("asn"), "as_owner": attrs.get("as_owner"), "country": attrs.get("country"),
            "creation_date": attrs.get("creation_date"), "registrar": attrs.get("registrar"),
        }
        summary = f"{mal} malicious, {sus} suspicious, {stats.get('harmless', 0)} harmless, {stats.get('undetected', 0)} undetected"
        return self.result(indicator_type, indicator, "success", verdict=verdict, summary=summary, data=data)
