import pytest

from app.services.email_parser.attachments import analyze_attachment
from app.services.email_parser.parser import EmailParseError, parse_email
from app.services.email_parser.urls import extract_urls
from app.services.header_forensics.forensics import analyze_headers
from app.services.ip_domain_intelligence.indicators import extract_indicators
from tests.conftest import sample_bytes


def test_parse_phishing_headers_and_bodies():
    p = parse_email(sample_bytes("phishing.eml"))
    h = p["headers"]
    assert h["from"]["address"] == "security@ntbamk.example"
    assert h["from"]["display_name"] == "NTBank Security Team"
    assert h["reply_to"]["domain"] == "ntbank-support.example"
    assert h["return_path"]["domain"] == "mailer-ntbamk.example"
    assert h["to"][0]["address"] == "analyst@corp.example"
    assert h["subject"].startswith("URGENT")
    assert h["x_mailer"].startswith("PHPMailer")
    assert len(p["received"]) == 2 and len(p["authentication_results"]) == 1
    assert "suspended" in p["body_text"] and "<a href" in p["body_html"]
    assert len(p["sha256"]) == 64


def test_url_extraction_text_and_html_with_display_text():
    urls = extract_urls("see https://a.example/x, and www.b.example.", '<a href="http://evil.example/login">https://bank.example</a>')
    by = {u["url"]: u for u in urls}
    assert "https://a.example/x" in by and "http://www.b.example" in by
    assert by["http://evil.example/login"]["display_texts"] == ["https://bank.example"]


def test_attachments_are_hashed_and_flagged():
    p = parse_email(sample_bytes("suspicious_url.eml"))
    names = {a["filename"]: a for a in p["attachments"]}
    js = names["Shared_Document.pdf.js"]
    assert {f["code"] for f in js["flags"]} >= {"script", "double_extension"}
    assert js["executed"] is False and len(js["sha256"]) == 64
    assert "macro_enabled" in {f["code"] for f in names["Q3_report.docm"]["flags"]}


def test_attachment_magic_mismatch_and_executable():
    a = analyze_attachment("invoice.pdf", "application/pdf", b"MZ\x90\x00rest")
    codes = {f["code"] for f in a["flags"]}
    assert "executable" in codes and "content_extension_mismatch" in codes
    rtlo = analyze_attachment("report‮fdp.exe", "application/octet-stream", b"MZ")
    assert "rtlo_character" in {f["code"] for f in rtlo["flags"]}


def test_indicator_extraction_roles():
    p = parse_email(sample_bytes("phishing.eml"))
    header, _ = analyze_headers(p, sample_bytes("phishing.eml"))
    ind = extract_indicators(p, header)
    assert "sending_ip" in ind.ips["185.220.101.47"]["roles"]
    assert "private_ip" in ind.ips["10.20.0.5"]["roles"]
    assert "reply_to_domain" in ind.domains["ntbank-support.example"]["roles"]
    assert "url_domain" in ind.domains["ntbank-secure-verify.example"]["roles"]
    assert ind.ips["185.220.101.47"]["id"] == "ip:185.220.101.47"
    assert "email:security@ntbamk.example" in {a["id"] for a in ind.addresses.values()}


def test_raw_text_input_and_invalid_input():
    raw = b"From: a@x.example\nTo: b@y.example\nSubject: hi\n\nhello https://x.example/p"
    p = parse_email(raw)
    assert p["urls"][0]["url"] == "https://x.example/p"
    with pytest.raises(EmailParseError):
        parse_email(b"")
    with pytest.raises(EmailParseError):
        parse_email(b"just some random text without headers")
