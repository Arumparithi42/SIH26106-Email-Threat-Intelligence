import subprocess

import dkim
import pytest

from app.core import dns as dnsx
from app.services.email_parser.parser import parse_email
from app.services.header_forensics import authentication as auth
from app.services.header_forensics.forensics import analyze_headers
from app.services.header_forensics.received import build_received_chain, parse_received_header, pick_sending_ip
from tests.conftest import sample_bytes, txt

R_NEW = "from mx1.corp.example (mx1.corp.example [10.20.0.5]) by mbox.corp.example with ESMTP id A; Tue, 22 Sep 2026 11:02:41 +0000"
R_OLD = "from evil.example (unknown [185.220.101.47]) by mx1.corp.example with ESMTP id B; Tue, 22 Sep 2026 11:02:39 +0000"


def test_parse_received_header_fields():
    h = parse_received_header(R_OLD)
    assert h["from_ip"] == "185.220.101.47" and h["from_helo"] == "evil.example"
    assert h["by_hostname"] == "mx1.corp.example" and h["protocol"] == "ESMTP"
    assert h["timestamp_dt"].year == 2026


def test_chain_is_chronological_with_deltas():
    hops, anomalies = build_received_chain([R_NEW, R_OLD], None)  # file order = newest first
    assert [h["hop"] for h in hops] == [1, 2]
    assert hops[0]["ip"] == "185.220.101.47" and hops[1]["ip"] == "10.20.0.5"
    assert hops[1]["time_delta_seconds"] == 2
    assert hops[1]["trust"] == "recorded_by_final_receiver"


def test_backwards_timestamp_is_anomaly_not_verdict():
    later_old = R_OLD.replace("11:02:39", "12:30:00")
    hops, anomalies = build_received_chain([R_NEW, later_old], None)
    a = [x for x in anomalies if x["code"] == "timestamp_backwards"]
    assert a and "investigation" in a[0]["interpretation"]


def test_sending_ip_prefers_trusted_receiver_client_ip():
    hops, _ = build_received_chain([R_NEW, R_OLD], None)
    assert pick_sending_ip(hops, None)["ip"] == "185.220.101.47"
    assert pick_sending_ip(hops, "40.92.58.21")["ip"] == "40.92.58.21"
    assert pick_sending_ip([], None)["ip"] is None


def test_identity_mismatches():
    p = parse_email(sample_bytes("phishing.eml"))
    result, findings = analyze_headers(p, sample_bytes("phishing.eml"))
    comp = {c["field"]: c for c in result["identity"]["comparisons"]}
    assert comp["reply_to"]["aligned_with_from"] is False
    assert comp["return_path"]["aligned_with_from"] is False
    ids = {f.finding_id for f in findings}
    assert {"F-ID-REPLYTO-MISMATCH", "F-ID-RETURNPATH-MISMATCH", "F-HDR-SUSPICIOUS-MAILER"} <= ids


def test_spf_status_mapping(monkeypatch):
    receiver = {"spf": None, "trusted": False}
    for raw, expected in [("pass", "pass"), ("fail", "fail"), ("softfail", "softfail"), ("temperror", "error"), ("permerror", "error")]:
        monkeypatch.setattr(auth, "spf_check", lambda ip, s, h, r=raw: (r, "fake"))
        assert auth.check_spf("185.220.101.47", "x@a.example", "a.example", None, receiver)["status"] == expected
    assert auth.check_spf(None, None, "a.example", None, receiver)["status"] == "unknown"


def test_receiver_result_used_only_when_trusted(monkeypatch):
    monkeypatch.setattr(auth, "spf_check", lambda ip, s, h: ("none", "no record"))
    trusted = auth.parse_receiver_results(["mx1.corp.example; spf=pass smtp.mailfrom=a.example"], [], "mbox.corp.example")
    forged = auth.parse_receiver_results(["attacker.example; spf=pass smtp.mailfrom=a.example"], [], "mbox.corp.example")
    assert trusted["trusted"] and not forged["trusted"]
    r1 = auth.check_spf("1.2.3.4", "x@a.example", "a.example", None, trusted)
    r2 = auth.check_spf("1.2.3.4", "x@a.example", "a.example", None, forged)
    assert (r1["status"], r1["status_source"]) == ("pass", "receiver_reported")
    assert (r2["status"], r2["status_source"]) == ("none", "independent_check")


@pytest.fixture(scope="module")
def dkim_key(tmp_path_factory):
    d = tmp_path_factory.mktemp("dkim")
    try:
        subprocess.run(["openssl", "genrsa", "-out", str(d / "k.pem"), "2048"], check=True, capture_output=True)
        pub = subprocess.run(["openssl", "rsa", "-in", str(d / "k.pem"), "-pubout", "-outform", "DER"], check=True, capture_output=True).stdout
    except (FileNotFoundError, subprocess.CalledProcessError):
        pytest.skip("openssl not available")
    import base64
    return (d / "k.pem").read_bytes(), "v=DKIM1; k=rsa; p=" + base64.b64encode(pub).decode()


def _signed(key: bytes) -> bytes:
    msg = b"From: a@signer.example\r\nTo: b@x.example\r\nSubject: test\r\nDate: Tue, 22 Sep 2026 10:00:00 +0000\r\n\r\nHello body\r\n"
    return dkim.sign(msg, b"sel", b"signer.example", key, include_headers=[b"from", b"to", b"subject", b"date"]) + msg


def test_dkim_pass_fail_and_missing_key(fake_dns, dkim_key):
    key, pub = dkim_key
    signed = _signed(key)
    sigs = [parse_email(signed)["dkim_signatures"][0]]
    no_receiver = {"trusted": False}
    fake_dns[("sel._domainkey.signer.example", "TXT")] = txt(pub)
    ok = auth.check_dkim(signed, sigs, no_receiver)
    assert ok["status"] == "pass" and ok["domain"] == "signer.example"
    tampered = signed.replace(b"Hello body", b"Hello BODY")
    assert auth.check_dkim(tampered, sigs, no_receiver)["status"] == "fail"
    del fake_dns[("sel._domainkey.signer.example", "TXT")]
    missing = auth.check_dkim(signed, sigs, no_receiver)
    assert missing["status"] == "error" and "not found" in missing["evidence"]
    assert auth.check_dkim(b"From: a@b.example\r\n\r\nx", [], no_receiver)["status"] == "none"


def test_dmarc_alignment_pass_fail_none_and_dns_error(fake_dns):
    fake_dns[("_dmarc.brand.example", "TXT")] = txt("v=DMARC1; p=reject; adkim=r; aspf=r")
    recv = {"trusted": False}
    spf_ok = {"status": "pass", "domain": "mail.brand.example"}  # relaxed alignment: same org domain
    spf_other = {"status": "pass", "domain": "other.example"}
    no_dkim = {"status": "none", "signatures": []}
    passed = auth.check_dmarc("brand.example", spf_ok, no_dkim, recv)
    assert passed["status"] == "pass" and passed["spf_alignment"] == "pass" and passed["policy"] == "reject"
    failed = auth.check_dmarc("brand.example", spf_other, no_dkim, recv)
    assert failed["status"] == "fail" and failed["spf_alignment"] == "fail"
    assert auth.check_dmarc("nodmarc.example", spf_ok, no_dkim, recv)["status"] == "none"
    fake_dns[("_dmarc.down.example", "TXT")] = dnsx.DNSResult("unavailable", error="timeout")
    assert auth.check_dmarc("down.example", spf_ok, no_dkim, recv)["status"] == "error"


def test_single_auth_failure_is_not_a_phishing_verdict():
    from app.services.risk_engine.engine import assess_risk
    from app.services.findings import finding
    f = [finding("F-AUTH-SPF-FAIL", category="authentication", severity="high", confidence="high", title="spf", description="d"),
         finding("F-AUTH-DMARC-FAIL", category="authentication", severity="high", confidence="high", title="dmarc", description="d")]
    r = assess_risk(f, {"ml": {}}, {"authentication": {}}, {})
    assert r.risk_level in ("LOW", "MEDIUM") and r.caps_applied
