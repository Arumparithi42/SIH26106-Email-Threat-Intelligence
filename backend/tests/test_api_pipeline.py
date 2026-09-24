"""End-to-end: API endpoints + full pipeline in zero-API-key mode, graph, timeline, PDF."""
import pytest
from fastapi.testclient import TestClient

from app.main import app
from tests.conftest import SAMPLES, sample_bytes

client = TestClient(app)


def analyze(name: str) -> dict:
    with (SAMPLES / name).open("rb") as fh:
        resp = client.post("/api/analyze/email", files={"file": (name, fh, "message/rfc822")})
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_health_never_exposes_keys():
    body = client.get("/api/health").json()
    assert body["status"] == "ok" and body["providers"]["ipqualityscore"] is False
    assert all(isinstance(v, bool) for v in body["providers"].values())


def test_phishing_end_to_end_zero_keys():
    r = analyze("phishing.eml")
    assert r["schema_version"] == "1.0" and r["analysis_id"].startswith("an_")
    for key in ("email", "threat_detection", "header_forensics", "indicators", "ip_intelligence", "domain_intelligence",
                "correlation", "findings", "risk_assessment", "timeline", "report"):
        assert key in r
    risk = r["risk_assessment"]
    assert risk["risk_level"] in ("HIGH", "CRITICAL") and risk["classification"] == "phishing"
    assert risk["reasons"] and risk["contributions"]
    # providers without keys are skipped, not crashing
    ipqs = [p for ip in r["ip_intelligence"] for p in ip["providers"] if p["provider"] == "ipqualityscore"]
    assert ipqs and ipqs[0]["status"] == "skipped" and ipqs[0]["summary"] == "Not configured"
    f = r["findings"][0]
    for field in ("finding_id", "category", "severity", "confidence", "title", "description", "evidence", "sources", "related_indicators"):
        assert field in f
    rels = {e["relation"] for e in r["correlation"]["edges"]}
    assert {"SENT_FROM", "REPLY_TO", "USES_DOMAIN", "ROUTED_THROUGH", "CONTAINS_URL", "HOSTED_BY"} <= rels
    node_ids = {n["id"] for n in r["correlation"]["nodes"]}
    assert "email:security@ntbamk.example" in node_ids and "ip:185.220.101.47" in node_ids
    stages = [t["event"] for t in r["timeline"] if t["kind"] == "investigation"]
    for expected in ("Email received", "Email parsed", "Threat detection completed", "Headers analyzed", "SPF checked", "DKIM checked",
                     "DMARC checked", "URLs and indicators extracted", "IP intelligence completed", "Domain intelligence completed",
                     "Threat graph generated", "Risk calculated", "Forensic report generated"):
        assert expected in stages
    aid = r["analysis_id"]
    assert client.get(f"/api/analysis/{aid}").json()["analysis_id"] == aid
    assert client.get(f"/api/analysis/{aid}/graph").json()["nodes"]
    assert client.get(f"/api/analysis/{aid}/timeline").json()[0]["timestamp"]
    pdf = client.get(f"/api/analysis/{aid}/report")
    assert pdf.status_code == 200 and pdf.headers["content-type"] == "application/pdf" and pdf.content.startswith(b"%PDF")
    assert any(a["analysis_id"] == aid for a in client.get("/api/analyses").json())


def test_legitimate_is_low_risk():
    r = analyze("legitimate.eml")
    assert r["risk_assessment"]["risk_level"] == "LOW"
    assert r["header_forensics"]["authentication"]["dmarc"]["status"] == "pass"


@pytest.mark.parametrize("name", ["spoofing.eml", "bec.eml", "suspicious_url.eml"])
def test_other_samples_are_flagged(name):
    assert analyze(name)["risk_assessment"]["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")


def test_raw_email_form_field():
    resp = client.post("/api/analyze/email", data={"raw_email": sample_bytes("bec.eml").decode()})
    assert resp.status_code == 200 and resp.json()["input"]["filename"] is None


def test_errors():
    assert client.post("/api/analyze/email").status_code == 400
    assert client.post("/api/analyze/email", files={"file": ("x.eml", b"not an email at all", "text/plain")}).status_code == 422
    assert client.get("/api/analysis/an_doesnotexist").status_code == 404
    big = b"From: a@b.example\n\n" + b"x" * (11 * 1024 * 1024)
    assert client.post("/api/analyze/email", files={"file": ("big.eml", big, "message/rfc822")}).status_code == 413


def test_provider_failure_does_not_break_analysis(monkeypatch):
    from app.services.ip_domain_intelligence import intelligence

    def boom(*a, **k):
        raise RuntimeError("provider layer exploded")
    monkeypatch.setattr(intelligence, "run_lookup", boom)
    r = analyze("phishing.eml")
    assert r["risk_assessment"]["risk_level"] in ("HIGH", "CRITICAL")
    assert any(t["status"] == "error" for t in r["timeline"])


def test_cross_analysis_correlation_ignores_recipient_infrastructure():
    analyze("phishing.eml")
    r = analyze("suspicious_url.eml")  # shares sending IP 185.220.101.47 with phishing.eml
    shared = {i for rel in r["correlation"]["related_analyses"] for i in rel["shared_indicators"]}
    assert "ip:185.220.101.47" in shared
    assert "ip:10.20.0.5" not in shared and "domain:corp.example" not in shared
