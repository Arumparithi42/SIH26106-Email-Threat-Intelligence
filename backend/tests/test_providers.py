"""Provider framework tests (IPQS as the worked example) - all HTTP is mocked."""
import logging

import httpx
import pytest

from app.core.config import Settings
from app.providers.abuseipdb import AbuseIPDBProvider
from app.providers.base import LookupContext, run_lookup
from app.providers.ipqs import IPQSProvider
from app.providers.virustotal import VirusTotalProvider

KEY = "TESTKEY-ipqs-0123456789"
IP = "185.220.101.47"
MOCK_OK = {  # _MOCK: canned response shape, not real intelligence
    "success": True, "message": "Success", "fraud_score": 88, "country_code": "DE", "city": "Demo", "region": "Demo",
    "ISP": "Demo ISP", "ASN": 64500, "organization": "Demo Org", "latitude": 0, "longitude": 0, "is_crawler": False,
    "proxy": True, "vpn": True, "tor": True, "active_vpn": False, "active_tor": True, "recent_abuse": True,
    "bot_status": False, "abuse_velocity": "high", "connection_type": "Data Center", "host": "demo.example", "request_id": "MOCK",
}


class Recorder:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        r = self.responses[min(self.calls - 1, len(self.responses) - 1)]
        if isinstance(r, Exception):
            raise r
        return r


def ctx_with(handler, **settings_kw) -> tuple[LookupContext, Settings]:
    s = Settings(ipqs_api_key=KEY, **settings_kw)
    return LookupContext(s, httpx.Client(transport=httpx.MockTransport(handler))), s


def ipqs(s):
    return IPQSProvider(s)


def test_missing_key_is_skipped_without_http():
    rec = Recorder([httpx.Response(200, json=MOCK_OK)])
    ctx, s = ctx_with(rec)
    s.ipqs_api_key = ""
    r = run_lookup(IPQSProvider(s), "ip", IP, ctx)
    assert (r.status, r.reason_code, r.summary) == ("skipped", "no_api_key", "Not configured") and rec.calls == 0


def test_success_maps_evidence_and_nulls_premium_fields():
    ctx, s = ctx_with(Recorder([httpx.Response(200, json=MOCK_OK)]))
    r = run_lookup(ipqs(s), "ip", IP, ctx)
    assert r.status == "success" and r.verdict == "suspicious"  # verdict from recent_abuse only
    d = r.data
    assert d["proxy"] is True and d["vpn"] is True and d["tor"] is True and d["connection_type"] == "Data Center"
    assert d["active_vpn"] is None and d["active_tor"] is None and d["abuse_velocity"] is None  # free plan
    assert d["fraud_score"] == 88 and "not used" in d["fraud_score_note"]


def test_premium_fields_kept_when_enabled():
    ctx, s = ctx_with(Recorder([httpx.Response(200, json=MOCK_OK)]), ipqs_premium_fields=True)
    d = run_lookup(ipqs(s), "ip", IP, ctx).data
    assert d["active_tor"] is True and d["active_vpn"] is False and d["abuse_velocity"] == "high"


def test_credits_exhausted_sets_backoff_and_stops_calling():
    rec = Recorder([httpx.Response(200, json={"success": False, "message": "You have insufficient credits to make this query."})])
    ctx, s = ctx_with(rec)
    r = run_lookup(ipqs(s), "ip", IP, ctx)
    assert (r.status, r.reason_code) == ("rate_limited", "quota_exhausted")
    ctx2, s2 = ctx_with(rec)  # a later analysis
    r2 = run_lookup(ipqs(s2), "ip", "185.220.101.33", ctx2)
    assert (r2.status, r2.reason_code) == ("rate_limited", "provider_backoff") and rec.calls == 1


def test_http_429_is_rate_limited():
    ctx, s = ctx_with(Recorder([httpx.Response(429)]))
    r = run_lookup(ipqs(s), "ip", IP, ctx)
    assert (r.status, r.reason_code) == ("rate_limited", "rate_limited")


def test_timeout_is_unavailable_after_one_retry():
    rec = Recorder([httpx.ReadTimeout("slow")])
    ctx, s = ctx_with(rec)
    r = run_lookup(ipqs(s), "ip", IP, ctx)
    assert (r.status, r.reason_code) == ("unavailable", "timeout") and rec.calls == 2


def test_server_error_retried_once():
    rec = Recorder([httpx.Response(500), httpx.Response(500)])
    ctx, s = ctx_with(rec)
    r = run_lookup(ipqs(s), "ip", IP, ctx)
    assert (r.status, r.reason_code) == ("unavailable", "http_5xx") and rec.calls == 2


def test_invalid_key_and_bad_json():
    ctx, s = ctx_with(Recorder([httpx.Response(200, json={"success": False, "message": "Invalid or unauthorized key."})]))
    assert run_lookup(ipqs(s), "ip", IP, ctx).reason_code == "invalid_key"
    ctx, s = ctx_with(Recorder([httpx.Response(200, content=b"<html>not json</html>")]))
    r = run_lookup(ipqs(s), "ip", "185.220.101.1", ctx)
    assert (r.status, r.reason_code) == ("error", "bad_response")


def test_cache_hit_and_errors_not_cached():
    rec = Recorder([httpx.Response(200, json=MOCK_OK)])
    ctx, s = ctx_with(rec)
    first, second = run_lookup(ipqs(s), "ip", IP, ctx), run_lookup(ipqs(s), "ip", IP, ctx)
    assert first.cached is False and second.cached is True and rec.calls == 1
    rec2 = Recorder([httpx.Response(500)])
    ctx, s = ctx_with(rec2)
    run_lookup(ipqs(s), "ip", "185.220.101.99", ctx)
    run_lookup(ipqs(s), "ip", "185.220.101.99", ctx)
    assert rec2.calls == 4  # 2 attempts each, nothing cached


def test_budget_and_private_ip():
    rec = Recorder([httpx.Response(200, json=MOCK_OK)])
    ctx, s = ctx_with(rec, ipqs_max_lookups_per_analysis=2)
    results = [run_lookup(ipqs(s), "ip", ip, ctx) for ip in ("185.220.101.1", "185.220.101.2", "185.220.101.3")]
    assert [r.status for r in results] == ["success", "success", "skipped"] and results[2].reason_code == "budget_exceeded"
    r = run_lookup(ipqs(s), "ip", "10.0.0.5", ctx)
    assert r.reason_code == "private_ip" and rec.calls == 2


def test_api_key_never_logged(caplog):
    caplog.set_level(logging.DEBUG)
    ctx, s = ctx_with(Recorder([httpx.ReadTimeout("slow")]))
    run_lookup(ipqs(s), "ip", IP, ctx)
    assert KEY not in caplog.text


def test_virustotal_not_found_is_unknown_not_safe():
    ctx, s = ctx_with(Recorder([httpx.Response(404, json={"error": {"code": "NotFoundError"}})]), virustotal_api_key="vt")
    r = run_lookup(VirusTotalProvider(s), "domain", "new-domain.example", ctx)
    assert r.status == "unknown" and r.verdict == "unknown"


def test_virustotal_detection_counts():
    body = {"data": {"attributes": {"last_analysis_stats": {"malicious": 5, "suspicious": 1, "harmless": 60, "undetected": 20},
                                    "last_analysis_results": {"VendorA": {"category": "malicious"}}}}}
    ctx, s = ctx_with(Recorder([httpx.Response(200, json=body)]), virustotal_api_key="vt")
    r = run_lookup(VirusTotalProvider(s), "url", "http://x.example/a", ctx)
    assert r.verdict == "malicious" and r.data["flagged_by"] == ["VendorA"]


@pytest.mark.parametrize("score,verdict", [(90, "malicious"), (40, "suspicious"), (0, "no_detections")])
def test_abuseipdb_mapping(score, verdict):
    body = {"data": {"abuseConfidenceScore": score, "totalReports": 3, "usageType": "Data Center/Web Hosting/Transit", "isTor": False}}
    ctx, s = ctx_with(Recorder([httpx.Response(200, json=body)]), abuseipdb_api_key="k")
    assert run_lookup(AbuseIPDBProvider(s), "ip", IP, ctx).verdict == verdict


def test_abuseipdb_daily_limit_backs_off():
    ctx, s = ctx_with(Recorder([httpx.Response(429)]), abuseipdb_api_key="k")
    r = run_lookup(AbuseIPDBProvider(s), "ip", IP, ctx)
    assert (r.status, r.reason_code) == ("rate_limited", "quota_exhausted")
