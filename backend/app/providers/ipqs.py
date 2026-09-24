"""IPQualityScore (IPQS) Proxy & VPN Detection API.

Used ONLY for anonymization / abuse evidence: proxy, vpn, tor, active_vpn,
active_tor, connection_type, recent_abuse (+ premium abuse_velocity, bot_status).
`fraud_score` is stored for reference and is never used as the project's score.

IPQS reports most problems as HTTP 200 with {"success": false, "message": ...},
so failures are classified from the message text.
Note: the API key is part of the URL path - never log the request URL.
"""
from __future__ import annotations

import httpx

from app.providers.base import Provider, ProviderFailure
from app.schemas.report import ProviderResult

BASE_URL = "https://ipqualityscore.com/api/json/ip"
EVIDENCE_FIELDS = ["proxy", "vpn", "tor", "active_vpn", "active_tor", "recent_abuse", "bot_status", "abuse_velocity",
                   "connection_type", "is_crawler", "host", "ISP", "ASN", "organization", "country_code", "city", "region",
                   "latitude", "longitude", "mobile", "fraud_score", "request_id"]
PREMIUM_FIELDS = ["active_vpn", "active_tor", "bot_status", "abuse_velocity"]


def classify_failure(message: str) -> ProviderFailure:
    m = (message or "").lower()
    if "credit" in m or "quota" in m or "insufficient" in m or "exceeded your" in m:
        return ProviderFailure("rate_limited", "quota_exhausted", message, backoff=True)
    if "too many" in m or "rate" in m or "per second" in m:
        return ProviderFailure("rate_limited", "rate_limited", message)
    if "key" in m and ("invalid" in m or "not" in m or "disabled" in m or "unauthori" in m):
        return ProviderFailure("error", "invalid_key", message)
    return ProviderFailure("error", "provider_error", message or "IPQS returned success=false")


class IPQSProvider(Provider):
    name = "ipqualityscore"
    supported_types = {"ip"}
    budget_limit_attr = "ipqs_max_lookups_per_analysis"

    def is_configured(self) -> bool:
        return bool(self.settings.ipqs_api_key)

    def cache_variant(self) -> str:
        return f"s{self.settings.ipqs_strictness}"

    def fetch(self, client: httpx.Client, indicator_type: str, indicator: str) -> ProviderResult:
        resp = client.get(f"{BASE_URL}/{self.settings.ipqs_api_key}/{indicator}",
                          params={"strictness": self.settings.ipqs_strictness, "allow_public_access_points": "true"})
        if resp.status_code == 429:
            raise ProviderFailure("rate_limited", "rate_limited", "HTTP 429 Too Many Requests")
        resp.raise_for_status()
        body = resp.json()
        if not isinstance(body, dict):
            raise ValueError("response is not a JSON object")
        if not body.get("success", False):
            raise classify_failure(str(body.get("message", "")))
        data = {k: body.get(k) for k in EVIDENCE_FIELDS}
        premium = self.settings.ipqs_premium_fields
        if not premium:
            for k in PREMIUM_FIELDS:
                data[k] = None  # a free-plan 'false' must not be read as 'checked and clean'
        data["premium_fields_available"] = premium
        data["strictness"] = self.settings.ipqs_strictness
        data["fraud_score_note"] = "IPQS proprietary score, stored for reference only; not used in any project score"
        verdict = "suspicious" if body.get("recent_abuse") is True else "no_detections"
        flags = [k for k in ("proxy", "vpn", "tor") if body.get(k) is True]
        summary = f"recent_abuse={body.get('recent_abuse')}; flags={','.join(flags) or 'none'}; connection_type={body.get('connection_type')}"
        return self.result(indicator_type, indicator, "success", verdict=verdict, summary=summary, data=data)
