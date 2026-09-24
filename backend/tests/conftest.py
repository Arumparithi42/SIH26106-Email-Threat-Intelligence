"""Test setup: isolated temp DB, no API keys, no network.

DNS and SPF are replaced with fakes; HTTP providers are exercised with
httpx.MockTransport. Tests never need live API keys or internet access.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

TMP = Path(tempfile.mkdtemp(prefix="sih26106-tests-"))
os.environ.update({
    "DATABASE_URL": f"sqlite:///{TMP / 'test.db'}",
    "REPORTS_DIR": str(TMP / "reports"),
    "VIRUSTOTAL_API_KEY": "", "ABUSEIPDB_API_KEY": "", "IPQS_API_KEY": "", "GOOGLE_SAFE_BROWSING_API_KEY": "",
    "MAXMIND_CITY_DB_PATH": str(TMP / "none-city.mmdb"), "MAXMIND_ASN_DB_PATH": str(TMP / "none-asn.mmdb"),
    "ENABLE_PUBLIC_FEEDS": "false", "ENABLE_RDAP": "false", "ENABLE_DNS": "true",
    "PROTECTED_DOMAINS": "ntbank.example", "LOG_LEVEL": "WARNING",
})
BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
SAMPLES = BACKEND.parent / "samples"

from app.core import dns as dnsx  # noqa: E402
from app.core.config import get_settings  # noqa: E402
from app.database.db import init_db, session_scope  # noqa: E402
from app.database.models import ProviderCache, ProviderState  # noqa: E402

get_settings.cache_clear()
init_db()


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch):
    """Offline DNS: tests put records in this dict; everything else is NXDOMAIN."""
    from app.providers import feeds
    from app.services.header_forensics import authentication

    dnsx.reset_state()
    feeds.reset_feeds()
    records: dict[tuple[str, str], dnsx.DNSResult] = {}

    def resolve(name: str, rtype: str) -> dnsx.DNSResult:
        return records.get((name.lower().rstrip("."), rtype), dnsx.DNSResult("nxdomain", error="fake NXDOMAIN"))

    monkeypatch.setattr(dnsx, "resolve", resolve)
    monkeypatch.setattr(authentication, "spf_check", lambda ip, sender, helo: ("none", "fake: no SPF record"))
    with session_scope() as s:
        s.query(ProviderCache).delete()
        s.query(ProviderState).delete()
    yield records


def sample_bytes(name: str) -> bytes:
    return (SAMPLES / name).read_bytes()


def txt(*values: str) -> dnsx.DNSResult:
    return dnsx.DNSResult("success", list(values))
