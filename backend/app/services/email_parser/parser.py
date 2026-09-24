"""Stage 1 - Email collection.

Parses raw RFC 5322 bytes with the standard-library `email` package.
The email and its attachments are treated as untrusted DATA:
nothing is executed, rendered or fetched; attachments are only hashed in memory.
"""
from __future__ import annotations

import logging
import re
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime

from email_validator import EmailNotValidError, validate_email

from app.core.utils import iso, sha256_hex
from app.services.email_parser.attachments import analyze_attachment
from app.services.email_parser.urls import extract_urls, html_to_text

log = logging.getLogger(__name__)

_ENCODED_WORD = re.compile(r"=\?[^?]+\?[bBqQ]\?[^?]*\?=")
BODY_LIMIT = 20000  # characters kept in the report per body


class EmailParseError(ValueError):
    pass


def _address(raw: str | None) -> dict | None:
    if not raw:
        return None
    pairs = getaddresses([raw])
    if not pairs:
        return None
    name, addr = pairs[0]
    addr = addr.strip().lower()
    domain = addr.rsplit("@", 1)[1] if "@" in addr else None
    valid = False
    if addr:
        try:
            validate_email(addr, check_deliverability=False, test_environment=True)
            valid = True
        except EmailNotValidError:
            valid = False
    return {"raw": raw, "display_name": name or None, "address": addr or None, "domain": domain, "syntax_valid": valid}


def _address_list(raw_values: list[str]) -> list[dict]:
    out = []
    for name, addr in getaddresses(raw_values):
        if addr:
            addr = addr.strip().lower()
            out.append({"display_name": name or None, "address": addr, "domain": addr.rsplit("@", 1)[-1] if "@" in addr else None})
    return out


def _header_str(msg: EmailMessage, name: str) -> str | None:
    value = msg.get(name)
    return str(value) if value is not None else None


def _raw_header_values(raw_headers: list[tuple[str, str]], name: str) -> list[str]:
    lname = name.lower()
    return [v for k, v in raw_headers if k.lower() == lname]


def parse_email(raw: bytes) -> dict:
    """Parse raw email bytes into a structured dict. Raises EmailParseError if it's not an email."""
    if not raw or not raw.strip():
        raise EmailParseError("Empty input")
    try:
        msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as exc:  # noqa: BLE001
        raise EmailParseError(f"Could not parse email: {exc}") from exc
    if not msg.keys() or not (msg.get("From") or msg.get("Received") or msg.get("Subject")):
        raise EmailParseError("Input does not look like an RFC 5322 email (no From/Received/Subject headers)")

    # raw (undecoded) header list, in file order - keeps the forensic original
    compat = BytesParser(policy=policy.compat32).parsebytes(raw, headersonly=True)
    raw_headers = [(k, str(v)) for k, v in compat.items()]

    date_raw = _header_str(msg, "Date")
    date_iso = None
    if date_raw:
        try:
            date_iso = iso(parsedate_to_datetime(date_raw))
        except (TypeError, ValueError):
            date_iso = None

    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[dict] = []
    part_summary: list[dict] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        part_summary.append({"content_type": ctype, "disposition": disposition, "filename": filename, "charset": part.get_content_charset()})
        if filename or disposition == "attachment":
            payload = part.get_payload(decode=True) or b""
            attachments.append(analyze_attachment(filename, ctype, payload))
            continue
        if ctype in ("text/plain", "text/html"):
            try:
                content = part.get_content()
            except Exception:  # noqa: BLE001 - bad charset etc.
                content = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
            (text_parts if ctype == "text/plain" else html_parts).append(content)

    body_text = "\n".join(text_parts)
    body_html = "\n".join(html_parts)
    if not body_text and body_html:
        body_text = html_to_text(body_html)

    urls = extract_urls(body_text, body_html)

    headers = {
        "from": _address(_header_str(msg, "From")),
        "sender": _address(_header_str(msg, "Sender")),
        "to": _address_list(_raw_header_values(raw_headers, "To")),
        "cc": _address_list(_raw_header_values(raw_headers, "Cc")),
        "reply_to": _address(_header_str(msg, "Reply-To")),
        "return_path": _address(_header_str(msg, "Return-Path")),
        "subject": _header_str(msg, "Subject"),
        "date": date_raw,
        "date_iso": date_iso,
        "message_id": _header_str(msg, "Message-ID"),
        "user_agent": _header_str(msg, "User-Agent"),
        "x_mailer": _header_str(msg, "X-Mailer"),
        "x_originating_ip": _header_str(msg, "X-Originating-IP"),
        "mime_version": _header_str(msg, "MIME-Version"),
        "content_type": msg.get_content_type(),
    }
    encoded_headers = [k for k, v in raw_headers if k.lower() in ("from", "subject", "reply-to", "to") and _ENCODED_WORD.search(v)]

    return {
        "sha256": sha256_hex(raw),
        "size_bytes": len(raw),
        "headers": headers,
        "raw_headers": [{"name": k, "value": v} for k, v in raw_headers],
        "received": _raw_header_values(raw_headers, "Received"),
        "authentication_results": _raw_header_values(raw_headers, "Authentication-Results"),
        "received_spf": _raw_header_values(raw_headers, "Received-SPF"),
        "dkim_signatures": _raw_header_values(raw_headers, "DKIM-Signature"),
        "encoded_headers": encoded_headers,
        "mime": {"content_type": msg.get_content_type(), "is_multipart": msg.is_multipart(), "parts": part_summary},
        "body_text": body_text[:BODY_LIMIT],
        "body_html": body_html[:BODY_LIMIT],
        "body_truncated": len(body_text) > BODY_LIMIT or len(body_html) > BODY_LIMIT,
        "urls": urls,
        "attachments": attachments,
    }
