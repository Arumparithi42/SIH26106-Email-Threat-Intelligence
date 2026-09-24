"""Instantiate all providers from settings."""
from __future__ import annotations

from app.core.config import Settings
from app.providers.abuseipdb import AbuseIPDBProvider
from app.providers.base import Provider
from app.providers.feeds import OpenPhishProvider, SafeBrowsingProvider, TorExitListProvider
from app.providers.ipqs import IPQSProvider
from app.providers.maxmind import MaxMindProvider
from app.providers.rdap import RDAPProvider
from app.providers.virustotal import VirusTotalProvider


def build_providers(settings: Settings) -> dict[str, Provider]:
    providers = [
        MaxMindProvider(settings), AbuseIPDBProvider(settings), IPQSProvider(settings), VirusTotalProvider(settings),
        TorExitListProvider(settings), RDAPProvider(settings), OpenPhishProvider(settings), SafeBrowsingProvider(settings),
    ]
    return {p.name: p for p in providers}
