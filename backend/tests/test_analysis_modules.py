"""Threat detection, intelligence merge, URL analysis, graph and risk engine."""
from app.schemas.report import ProviderResult
from app.services.findings import finding
from app.services.ip_domain_intelligence.intelligence import _signal, assemble_ip, build_intel_findings
from app.services.ip_domain_intelligence.url_analysis import analyze_url, lookalike_of
from app.services.risk_engine.engine import assess_risk
from app.services.threat_detection import ml
from app.services.threat_detection.rules import infer_rule_category, match_rules, sender_impersonation


# ---------------------------------------------------------------- threat detection
def test_rules_detect_lures_and_respect_negation():
    groups = {h["group"] for h in match_rules("URGENT: your account has been suspended. Verify your account within 24 hours, click here.")}
    assert {"urgency", "account_threat", "credential", "call_to_action"} <= groups
    assert not match_rules("We will never ask for your password or OTP.")
    assert infer_rule_category({"financial", "secrecy_authority", "urgency"}, has_links=False, impersonation=False) == "bec"
    assert infer_rule_category({"credential", "call_to_action", "urgency"}, has_links=True, impersonation=False) == "phishing"


def test_display_name_impersonation():
    hits = sender_impersonation({"display_name": "IT Helpdesk", "address": "x@gmail.com", "domain": "gmail.com"}, [])
    assert hits[0]["code"] == "role_name_on_freemail"
    hits = sender_impersonation({"display_name": "boss@corp.example", "address": "x@evil.example", "domain": "evil.example"}, [])
    assert hits[0]["code"] == "display_name_address_mismatch"


def test_ml_classifier_returns_category_probability_and_real_metrics():
    r = ml.classify("Please process an urgent wire transfer to the new vendor bank account, keep it confidential")
    assert r["predicted_category"] == "bec" and 0 < r["probability"] <= 1
    assert abs(sum(r["probabilities"].values()) - 1) < 0.01
    m = ml.model_info()["metrics"]
    cm = m["confusion_matrix"]["matrix"]
    assert m["n_samples"] == sum(map(sum, cm)) == 105  # metrics computed from the actual dataset
    assert m["accuracy"] == round(sum(cm[i][i] for i in range(len(cm))) / 105, 4)


# ---------------------------------------------------------------- URL / lookalike
def test_url_characteristics():
    u = analyze_url({"url": "http://185.220.101.47:8080/login", "sources": ["html_href"], "display_texts": ["https://bank.example"]}, "bank.example", ["bank.example"])
    codes = {c["code"] for c in u["characteristics"]}
    assert {"ip_based_url", "non_standard_port", "no_tls", "credential_keywords", "display_text_mismatch"} <= codes
    assert u["visited"] is False
    at = analyze_url({"url": "http://bank.example@203.0.113.9/x"}, None, [])
    assert "at_sign_in_url" in {c["code"] for c in at["characteristics"]} and at["hostname"] == "203.0.113.9"


def test_lookalike_detection():
    assert lookalike_of("ntbamk.example", ["ntbank.example"]) == "ntbank.example"
    assert lookalike_of("ntbank-secure-verify.example", ["ntbank.example"]) == "ntbank.example"
    assert lookalike_of("ntbank.example", ["ntbank.example"]) is None
    assert lookalike_of("unrelated.example", ["ntbank.example"]) is None


# ---------------------------------------------------------------- IP intelligence merge
def _res(provider, data, status="success", verdict="unknown"):
    return ProviderResult(provider=provider, indicator="185.220.101.47", indicator_type="ip", status=status, verdict=verdict, data=data)


def test_signal_merge_rules():
    assert _signal([("tor_exit_list", "listed", True), ("ipqualityscore", "tor", False)])["value"] == "detected"
    assert _signal([("ipqualityscore", "vpn", False), ("ipqualityscore", "active_vpn", None)])["value"] == "not_detected"
    assert _signal([("ipqualityscore", "active_vpn", None)])["value"] == "unknown"
    assert _signal([])["value"] == "unknown"


def test_assemble_ip_uses_one_primary_source_per_question():
    ip = {"value": "185.220.101.47", "id": "ip:185.220.101.47", "roles": ["sending_ip"], "is_public": True}
    results = {
        "ipqualityscore": _res("ipqualityscore", {"vpn": True, "proxy": False, "tor": False, "active_vpn": None, "active_tor": None,
                                                   "connection_type": "Data Center", "ISP": "Demo", "ASN": 64500, "fraud_score": 99}),
        "tor_exit_list": _res("tor_exit_list", {"listed": True}),
        "abuseipdb": _res("abuseipdb", {"usageType": "Data Center/Web Hosting/Transit", "countryCode": "DE"}, verdict="suspicious"),
        "virustotal": _res("virustotal", {}, status="skipped"),
    }
    out = assemble_ip(ip, results)
    assert out["anonymization"]["tor"]["value"] == "detected"
    assert out["anonymization"]["vpn"]["value"] == "detected" and out["anonymization"]["hosting"]["value"] == "detected"
    assert out["geolocation"]["source"].startswith("country only") and out["geolocation"]["latitude"] is None
    assert out["network"]["source"] == "ipqualityscore"
    findings = build_intel_findings([out], [], [])
    ids = {f.finding_id for f in findings}
    assert "F-IP-TOR-185.220.101.47" in ids and "F-IP-VPN-PROXY-185.220.101.47" in ids
    assert all("fraud_score" not in (f.description + f.title) for f in findings)  # never used as a score


def test_unknown_reputation_does_not_create_findings():
    ip = {"value": "185.220.101.47", "id": "ip:185.220.101.47", "roles": ["relay_ip"], "is_public": True}
    out = assemble_ip(ip, {"virustotal": _res("virustotal", {}, status="unknown")})
    assert build_intel_findings([out], [], []) == []


# ---------------------------------------------------------------- risk engine
def _f(fid, cat, sev, conf="high"):
    return finding(fid, category=cat, severity=sev, confidence=conf, title=fid, description="d")


def test_risk_caps_single_dimension_and_tor_alone():
    only_tor = [_f("tor", "ip", "high")]
    r = assess_risk(only_tor, {"ml": {}}, {"authentication": {}}, {})
    assert r.risk_level in ("LOW", "MEDIUM")
    r = assess_risk([_f("a", "authentication", "critical"), _f("b", "authentication", "critical")], {"ml": {}}, {"authentication": {}}, {})
    assert r.risk_level == "MEDIUM" and r.caps_applied


def test_risk_critical_needs_three_dimensions_and_is_explained():
    fs = [_f("c", "content", "high"), _f("i", "identity", "high"), _f("u", "url", "critical")]
    r = assess_risk(fs, {"ml": {}, "rule_category": "phishing"}, {"authentication": {}}, {})
    assert r.risk_level == "CRITICAL" and len(r.evidence_dimensions) == 3
    assert sum(c.points for c in r.contributions) == r.risk_score  # every point is traceable
    assert r.classification == "phishing"


def test_mitigation_and_low_risk_classification():
    r = assess_risk([_f("pass", "mitigating", "info")], {"ml": {"predicted_category": "legitimate", "probability": 0.9}}, {"authentication": {}}, {})
    assert r.risk_level == "LOW" and r.classification == "legitimate"
