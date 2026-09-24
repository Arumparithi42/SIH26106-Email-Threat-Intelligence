"""MaxMind GeoLite2 City + ASN - offline, local database lookups (no network)."""
from __future__ import annotations

import threading
from pathlib import Path

import geoip2.database
import geoip2.errors
import httpx

from app.providers.base import Provider
from app.schemas.report import ProviderResult

_readers: dict[str, geoip2.database.Reader] = {}
_lock = threading.Lock()


def _reader(path: str) -> geoip2.database.Reader | None:
    if not Path(path).is_file():
        return None
    with _lock:
        if path not in _readers:
            _readers[path] = geoip2.database.Reader(path)
        return _readers[path]


class MaxMindProvider(Provider):
    name = "maxmind_geolite2"
    supported_types = {"ip"}
    requires_key = False
    cacheable = False  # local file lookup, no need to cache

    def is_configured(self) -> bool:
        return Path(self.settings.maxmind_city_db_path).is_file() or Path(self.settings.maxmind_asn_db_path).is_file()

    def fetch(self, client: httpx.Client, indicator_type: str, indicator: str) -> ProviderResult:
        data: dict = {}
        city_r, asn_r = _reader(self.settings.maxmind_city_db_path), _reader(self.settings.maxmind_asn_db_path)
        if city_r:
            try:
                c = city_r.city(indicator)
                data.update(country=c.country.name, country_code=c.country.iso_code,
                            region=c.subdivisions.most_specific.name if c.subdivisions else None, city=c.city.name,
                            latitude=c.location.latitude, longitude=c.location.longitude,
                            accuracy_radius_km=c.location.accuracy_radius)
            except geoip2.errors.AddressNotFoundError:
                pass
        if asn_r:
            try:
                a = asn_r.asn(indicator)
                data.update(asn=a.autonomous_system_number, as_org=a.autonomous_system_organization)
            except geoip2.errors.AddressNotFoundError:
                pass
        if not data:
            return self.result(indicator_type, indicator, "unknown", summary="IP not present in GeoLite2 databases")
        place = ", ".join(x for x in (data.get("city"), data.get("region"), data.get("country")) if x)
        return self.result(indicator_type, indicator, "success", verdict="unknown", data=data,
                           summary=f"{place or 'location n/a'}; AS{data.get('asn') or '?'} {data.get('as_org') or ''}".strip())
