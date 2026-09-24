"""Transparent rule/heuristic content detection.

Each rule is a named regex with a plain-language explanation. Matches are
evidence, not verdicts; the risk engine combines them with other modules.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    rule_id: str
    group: str  # urgency | account_threat | credential | password_reset | financial | secrecy_authority | call_to_action | reward | threat_intimidation
    label: str
    pattern: str


RULES: list[Rule] = [
    Rule("R-URG-1", "urgency", "Urgent / time-pressure language", r"\b(urgent(ly)?|immediately|asap|right away|as soon as possible|final (notice|warning|reminder)|act now|last chance)\b"),
    Rule("R-URG-2", "urgency", "Deadline pressure", r"\bwithin \d{1,3} ?(hours?|hrs?|minutes?|days?)\b|\b(today|by end of (the )?day|before (it'?s )?too late|expires? (today|soon|in))\b"),
    Rule("R-ACC-1", "account_threat", "Account suspension / lock threat", r"\b(account|mailbox|access|card|service|net ?banking)\b[^.\n]{0,40}\b(suspend(ed)?|lock(ed)?|block(ed)?|disabled?|deactivat(ed|e)|terminat(ed|e)|closed?|restricted)\b"),
    Rule("R-ACC-2", "account_threat", "Unusual activity claim", r"\b(unusual|suspicious|unauthori[sz]ed) (activity|sign[- ]?in|login|transactions?|access)\b"),
    Rule("R-CRED-1", "credential", "Request to verify / confirm identity or account", r"\b(verify|confirm|validate|re-?validate|update)\s+(your|the|my)\b[^.\n]{0,25}\b(account|identity|credentials?|details|information|kyc|email|login)\b"),
    Rule("R-CRED-2", "credential", "Asks for password, OTP, PIN or card data", r"\b(password|passcode|otp|one[- ]time password|pin|cvv|card number|login credentials|security code)\b"),
    Rule("R-PWD-1", "password_reset", "Password reset / expiry lure", r"\bpassword\b[^.\n]{0,30}\b(expir(e|es|ed|y)|reset|change)\b|\breset your password\b"),
    Rule("R-FIN-1", "financial", "Payment / wire transfer request", r"\b(wire transfer|bank transfer|rtgs|neft|imps|remit(tance)?|process (the |this )?payment|make (a |the )?payment|transfer (the )?funds?|pay (the|this) (invoice|vendor))\b"),
    Rule("R-FIN-2", "financial", "Bank-detail change", r"\b(new|updated|changed?)\b[^.\n]{0,25}\b(bank (account|details)|account number|beneficiary|ifsc|remittance account)\b"),
    Rule("R-FIN-3", "financial", "Gift card request", r"\bgift ?cards?\b|\b(google play|itunes|amazon) (cards?|vouchers?)\b"),
    Rule("R-FIN-4", "financial", "Invoice / payment-due pressure", r"\b(invoice|payment)\b[^.\n]{0,25}\b(overdue|pending|due|outstanding|declined|failed)\b"),
    Rule("R-SEC-1", "secrecy_authority", "Secrecy request", r"\b(confidential|keep (this|it) (between us|quiet|private)|do not (discuss|tell|share)|discreet(ly)?|quietly)\b"),
    Rule("R-SEC-2", "secrecy_authority", "Authority figure pressure", r"\b(ceo|cfo|managing director|director|chairman|president|board meeting|principal|vice chancellor)\b"),
    Rule("R-SEC-3", "secrecy_authority", "Unavailability excuse (cannot call)", r"\b(can(not|'t) (talk|call)|in a (meeting|board meeting)|travell?ing|do not call)\b"),
    Rule("R-CTA-1", "call_to_action", "Click / log-in call to action", r"\b(click (here|the (link|button)|below)|log ?in (here|now|below)|sign in (here|now|below)|open the (link|attachment)|download (the|now))\b"),
    Rule("R-REW-1", "reward", "Prize / refund / reward lure", r"\b(congratulations|you (have )?won|winner|lottery|prize|refund (of|is approved)|claim (it|your|now))\b"),
    Rule("R-THR-1", "threat_intimidation", "Legal / penalty intimidation", r"\b(legal action|penalty|fine|arrest|police complaint|court|disconnection notice|permanently deleted)\b"),
]
_COMPILED = [(r, re.compile(r.pattern, re.IGNORECASE)) for r in RULES]

GROUP_TEXT = {
    "urgency": ("Urgent or time-pressure language", "Pressure to act quickly is a classic social-engineering technique that discourages verification."),
    "account_threat": ("Account suspension / unusual-activity threat", "Threatening loss of access pushes the reader to act without checking the sender."),
    "credential": ("Request for credentials or verification", "Legitimate services rarely ask users to re-enter passwords, OTPs or card data via an email link."),
    "password_reset": ("Password reset / expiry lure", "Fake password-expiry notices are a common way to harvest credentials."),
    "financial": ("Payment, bank-detail or gift-card request", "Money-movement requests by email are the core of Business Email Compromise fraud."),
    "secrecy_authority": ("Secrecy or authority pressure", "Invoking an executive and asking for confidentiality bypasses normal approval checks."),
    "call_to_action": ("Click / log-in call to action", "Directs the reader to a link or login page, where credential theft usually happens."),
    "reward": ("Prize, refund or reward lure", "Unexpected rewards are used to bait readers into giving personal or bank details."),
    "threat_intimidation": ("Legal or penalty intimidation", "Threats of penalties create fear-driven compliance."),
}

FREEMAIL = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.in", "outlook.com", "hotmail.com", "live.com", "aol.com",
    "proton.me", "protonmail.com", "gmx.com", "mail.com", "yandex.com", "zoho.com", "icloud.com", "rediffmail.com",
}
ROLE_WORDS = re.compile(
    r"\b(bank|security|support|helpdesk|help desk|admin(istrator)?|it (department|team|services)|hr|human resources|payroll|"
    r"ceo|cfo|director|principal|registrar|customer care|service desk|billing|accounts?|official|team|department)\b",
    re.IGNORECASE,
)


def _snippet(text: str, start: int, end: int, pad: int = 45) -> str:
    s = max(0, start - pad)
    e = min(len(text), end + pad)
    return ("..." if s else "") + re.sub(r"\s+", " ", text[s:e]).strip() + ("..." if e < len(text) else "")


NEGATION = re.compile(r"\b(never|not|n't|no one|nobody|don't|do not|will not|won't)\b[^.\n]{0,40}$", re.IGNORECASE)
NEGATABLE_GROUPS = {"credential", "password_reset", "financial"}


def match_rules(text: str) -> list[dict]:
    """First non-negated match per rule ("we will never ask for your password" does not count)."""
    hits: list[dict] = []
    text = text or ""
    for rule, rx in _COMPILED:
        m = None
        for cand in rx.finditer(text):
            if rule.group in NEGATABLE_GROUPS and NEGATION.search(text[max(0, cand.start() - 60):cand.start()]):
                continue
            m = cand
            break
        if m:
            hits.append({
                "rule_id": rule.rule_id,
                "group": rule.group,
                "label": rule.label,
                "matched_text": m.group(0),
                "snippet": _snippet(text, m.start(), m.end()),
            })
    return hits


def sender_impersonation(from_hdr: dict | None, protected_labels: list[str]) -> list[dict]:
    """Display-name based impersonation checks."""
    if not from_hdr or not from_hdr.get("address"):
        return []
    out = []
    name = (from_hdr.get("display_name") or "").strip()
    domain = (from_hdr.get("domain") or "").lower()
    if not name:
        return out
    embedded = re.search(r"[\w.+-]+@([\w-]+(\.[\w-]+)+)", name)
    if embedded and embedded.group(1).lower() != domain:
        out.append({"code": "display_name_address_mismatch", "detail": f"Display name shows '{embedded.group(0)}' but the real address is '{from_hdr['address']}'"})
    if ROLE_WORDS.search(name) and domain in FREEMAIL:
        out.append({"code": "role_name_on_freemail", "detail": f"Display name '{name}' claims an organisational role but the address uses free webmail ({domain})"})
    lname = name.lower()
    for label in protected_labels:
        if label and label in lname.replace(" ", "") and label not in domain:
            out.append({"code": "brand_in_display_name", "detail": f"Display name references '{label}' but the sending domain is '{domain}'"})
    return out


def infer_rule_category(groups: set[str], has_links: bool, impersonation: bool) -> str | None:
    """Very simple, documented mapping from matched rule groups to a category."""
    phish_score = len(groups & {"credential", "password_reset", "account_threat", "call_to_action"}) + (1 if has_links else 0)
    bec_score = len(groups & {"financial", "secrecy_authority"}) * 2 + (1 if "urgency" in groups else 0) - (1 if has_links else 0)
    if phish_score >= 3 or (phish_score >= 2 and "urgency" in groups):
        return "phishing"
    if bec_score >= 3:
        return "bec"
    if impersonation:
        return "spoofing"
    if groups:
        return "suspicious"
    return None
