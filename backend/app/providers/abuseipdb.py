"""AbuseIPDB API v2 - abuse confidence score and community report history for IPs."""
from __future__ import annotations

import httpx

from app.providers.base import Provider, ProviderFailure
from app.schemas.report import ProviderResult

URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBProvider(Provider):
    name = "abuseipdb"
    supported_types = {"ip"}

    def is_configured(self) -> bool:
        return bool(self.settings.abuseipdb_api_key)

    def fetch(self, client: httpx.Client, indicator_type: str, indicator: str) -> ProviderResult:
        resp = client.get(URL, params={"ipAddress": indicator, "maxAgeInDays": 90},
                          headers={"Key": self.settings.abuseipdb_api_key, "Accept": "application/json"})
        if resp.status_code == 429:  # AbuseIPDB 429 = daily quota used up
            raise ProviderFailure("rate_limited", "quota_exhausted", "AbuseIPDB daily limit reached (HTTP 429)", backoff=True)
        resp.raise_for_status()
        d = resp.json()["data"]
        score = int(d.get("abuseConfidenceScore") or 0)
        reports = int(d.get("totalReports") or 0)
        verdict = "malicious" if score >= 75 else "suspicious" if score >= 25 else "no_detections"
        data = {k: d.get(k) for k in ("abuseConfidenceScore", "totalReports", "numDistinctUsers", "lastReportedAt", "usageType",
                                      "isp", "domain", "countryCode", "isTor", "isWhitelisted", "isPublic")}
        summary = f"Abuse confidence {score}/100 from {reports} report(s) in 90 days"
        return self.result(indicator_type, indicator, "success", verdict=verdict, summary=summary, data=data)
