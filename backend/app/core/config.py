"""Application settings loaded from environment variables / .env.

API keys live ONLY here (backend side). They are never sent to the frontend.
Every key is optional: a missing key simply disables that provider.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]
PROJECT_DIR = BACKEND_DIR.parent
DATA_DIR = BACKEND_DIR / "data"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(PROJECT_DIR / ".env", BACKEND_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ---- External provider keys (all optional) ----
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    ipqs_api_key: str = ""
    google_safe_browsing_api_key: str = ""

    # ---- MaxMind GeoLite2 (local database files) ----
    maxmind_city_db_path: str = str(DATA_DIR / "GeoLite2-City.mmdb")
    maxmind_asn_db_path: str = str(DATA_DIR / "GeoLite2-ASN.mmdb")

    # ---- IPQS behaviour ----
    ipqs_strictness: int = 0
    ipqs_premium_fields: bool = False
    ipqs_max_lookups_per_analysis: int = 2

    # ---- Other per-analysis budgets ----
    vt_max_lookups_per_analysis: int = 4
    provider_backoff_hours: int = 24

    # ---- Keyless sources (can be switched off, e.g. for offline demos/tests) ----
    enable_dns: bool = True
    enable_rdap: bool = True
    enable_public_feeds: bool = True  # Tor exit list + OpenPhish community feed

    # ---- Timeouts ----
    http_timeout_seconds: float = 8.0
    dns_timeout_seconds: float = 3.0

    # ---- Cache TTLs (hours) ----
    cache_ttl_hours: int = 24
    cache_ttl_unknown_hours: int = 6
    cache_ttl_rdap_hours: int = 168
    cache_ttl_feed_hours: int = 6

    # ---- Detection tuning ----
    # Comma-separated domains your organisation owns; look-alikes of these are flagged.
    # Default is the fictional demo bank used by /samples (reserved .example TLD).
    protected_domains: str = "ntbank.example"

    # ---- App ----
    database_url: str = f"sqlite:///{DATA_DIR / 'sih_email_intel.db'}"
    reports_dir: str = str(DATA_DIR / "reports")
    max_upload_mb: int = 10
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    log_level: str = "INFO"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def protected_domain_list(self) -> list[str]:
        return [d.strip().lower() for d in self.protected_domains.split(",") if d.strip()]

    def provider_configuration(self) -> dict[str, bool]:
        """Which providers are usable. Booleans only - never the keys."""
        return {
            "virustotal": bool(self.virustotal_api_key),
            "abuseipdb": bool(self.abuseipdb_api_key),
            "ipqualityscore": bool(self.ipqs_api_key),
            "google_safe_browsing": bool(self.google_safe_browsing_api_key),
            "maxmind_city": Path(self.maxmind_city_db_path).is_file(),
            "maxmind_asn": Path(self.maxmind_asn_db_path).is_file(),
            "dns": self.enable_dns,
            "rdap": self.enable_rdap,
            "tor_exit_list": self.enable_public_feeds,
            "openphish": self.enable_public_feeds,
        }


@lru_cache
def get_settings() -> Settings:
    return Settings()
