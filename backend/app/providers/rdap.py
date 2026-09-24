"""RDAP (modern WHOIS) - domain registration data via the public rdap.org bootstrap.

Missing/redacted registration data is common (privacy services, TLDs without RDAP)
and is reported as 'unknown' - never as suspicious by itself.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx

from app.core.utils import is_reserved_domain
from app.providers.base import Provider
from app.schemas.report import ProviderResult

URL = "https://rdap.org/domain/{}"


def _vcard_name(entity: dict) -> str | None:
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if item and item[0] == "fn":
            return item[3]
    return None


class RDAPProvider(Provider):
    name = "rdap"
    supported_types = {"domain"}
    requires_key = False

    def is_configured(self) -> bool:
        return self.settings.enable_rdap

    def ttl(self, result: ProviderResult) -> timedelta:
        return timedelta(hours=self.settings.cache_ttl_rdap_hours if result.status == "success" else self.settings.cache_ttl_unknown_hours)

    def fetch(self, client: httpx.Client, indicator_type: str, indicator: str) -> ProviderResult:
        if is_reserved_domain(indicator):
            return self.result(indicator_type, indicator, "unknown", summary="Reserved/documentation TLD - no registration data exists")
        resp = client.get(URL.format(indicator), headers={"Accept": "application/rdap+json"})
        if resp.status_code == 404:
            return self.result(indicator_type, indicator, "unknown", summary="No RDAP record (domain may not be registered, or its registry has no RDAP)")
        resp.raise_for_status()
        body = resp.json()
        events = {e.get("eventAction"): e.get("eventDate") for e in body.get("events", [])}
        created = events.get("registration")
        age_days = None
        if created:
            try:
                age_days = (datetime.now(timezone.utc) - datetime.fromisoformat(created.replace("Z", "+00:00"))).days
            except ValueError:
                pass
        registrar = next((_vcard_name(e) for e in body.get("entities", []) if "registrar" in (e.get("roles") or [])), None)
        data = {
            "created": created, "age_days": age_days, "expires": events.get("expiration"), "last_changed": events.get("last changed"),
            "registrar": registrar, "status": body.get("status"),
            "nameservers": [n.get("ldhName", "").lower() for n in body.get("nameservers", [])],
            "redacted": bool(body.get("redacted")) or any("redact" in str(r).lower() for r in body.get("remarks") or []),
        }
        summary = f"Registered {created[:10] if created else 'date n/a'}" + (f" ({age_days} days ago)" if age_days is not None else "") + (f"; registrar {registrar}" if registrar else "")
        return self.result(indicator_type, indicator, "success", verdict="unknown", summary=summary, data=data)
