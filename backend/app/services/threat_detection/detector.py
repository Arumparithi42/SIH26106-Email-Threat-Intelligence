"""Stage 2 - Threat detection: rules/heuristics + ML/NLP on the email content."""
from __future__ import annotations

from app.core.config import get_settings
from app.core.utils import domain_label
from app.services.findings import ev, finding
from app.services.threat_detection import ml
from app.services.threat_detection.rules import GROUP_TEXT, infer_rule_category, match_rules, sender_impersonation

GROUP_SEVERITY = {
    "credential": "medium", "password_reset": "medium", "financial": "medium", "account_threat": "low",
    "secrecy_authority": "low", "urgency": "low", "call_to_action": "low", "reward": "low", "threat_intimidation": "low",
}


def detect_threats(parsed: dict) -> tuple[dict, list]:
    headers = parsed["headers"]
    subject = headers.get("subject") or ""
    text = f"{subject}\n{parsed.get('body_text') or ''}"
    hits = match_rules(text)
    groups = {h["group"] for h in hits}

    protected = [domain_label(d) for d in get_settings().protected_domain_list]
    impersonation = sender_impersonation(headers.get("from"), protected)
    rule_category = infer_rule_category(groups, bool(parsed.get("urls")), bool(impersonation))
    ml_result = ml.classify(text)

    findings = []
    for group in sorted(groups):
        title, why = GROUP_TEXT[group]
        group_hits = [h for h in hits if h["group"] == group]
        findings.append(finding(
            f"F-CONTENT-{group.upper().replace('_', '-')}",
            category="content", severity=GROUP_SEVERITY[group], confidence="medium" if len(group_hits) > 1 else "low",
            title=title,
            description=f"{len(group_hits)} content rule(s) matched: " + "; ".join(h["label"] for h in group_hits),
            why=why,
            evidence=[ev(h["label"], h["snippet"], f"rule {h['rule_id']}") for h in group_hits],
            sources=["rule_engine"], module="threat_detection",
        ))
    for imp in impersonation:
        findings.append(finding(
            f"F-IMPERSONATION-{imp['code'].upper().replace('_', '-')}",
            category="identity", severity="medium", confidence="medium",
            title="Sender display name suggests impersonation",
            description=imp["detail"],
            why="Most mail clients show only the display name, so attackers put a trusted name or address there.",
            evidence=[ev("From header", (headers.get("from") or {}).get("raw"), "From")],
            sources=["rule_engine"], related=[f"email:{headers['from']['address']}"], module="threat_detection",
        ))
    pattern = {"phishing": ("Credential-phishing pattern", "Account-threat, verification/credential request and call-to-action appear together, the typical structure of a credential-phishing lure."),
               "bec": ("Business Email Compromise pattern", "A payment/bank-detail request combined with secrecy, authority or urgency is the typical structure of BEC fraud.")}
    if rule_category in pattern and len(groups) >= 3:
        title, why = pattern[rule_category]
        findings.append(finding(
            f"F-CONTENT-{rule_category.upper()}-PATTERN", category="content", severity="high", confidence="medium",
            title=title, description="Matched rule groups: " + ", ".join(sorted(groups)), why=why,
            sources=["rule_engine"], module="threat_detection"))
    if ml_result.get("status") == "success" and ml_result["predicted_category"] != "legitimate":
        p = ml_result["probability"]
        if p >= 0.45:
            findings.append(finding(
                "F-ML-CLASSIFICATION",
                category="ml", severity="medium" if p >= 0.7 else "low", confidence="medium" if p >= 0.7 else "low",
                title=f"ML text classifier predicts '{ml_result['predicted_category']}' (p={p:.2f})",
                description="TF-IDF + Logistic Regression model output on subject and body text. Influential terms: "
                + (", ".join(ml_result.get("top_terms") or []) or "n/a"),
                why="Statistical language patterns similar to known malicious examples; a supporting signal only.",
                evidence=[ev("class probabilities", ml_result["probabilities"], ml.MODEL_NAME, "analytical_finding")],
                sources=[ml.MODEL_NAME], module="threat_detection",
            ))

    result = {
        "rule_matches": hits,
        "matched_groups": sorted(groups),
        "rule_category": rule_category,
        "impersonation_indicators": impersonation,
        "ml": ml_result,
        "summary": {
            "rule_hits": len(hits),
            "ml_category": ml_result.get("predicted_category"),
            "ml_probability": ml_result.get("probability"),
            "rule_category": rule_category,
        },
    }
    return result, findings
