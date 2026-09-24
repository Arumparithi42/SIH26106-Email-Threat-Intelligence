"""Stage 6 - Transparent, evidence-based risk & confidence.

No black box: every point comes from a listed finding.

points(finding) = SEVERITY_POINTS[severity] x CONFIDENCE_FACTOR[confidence]
score           = clamp(sum(points) - mitigation, 0, 100)
level           = LOW <20 <= MEDIUM <45 <= HIGH <70 <= CRITICAL

Corroboration caps (a single weak signal can never produce a high risk):
- evidence from only 1 dimension  -> at most MEDIUM
- evidence from only 2 dimensions -> at most HIGH
- CRITICAL needs >= 3 dimensions AND at least one high/critical finding
So "SPF fail", "Tor", "new domain" or "foreign country" alone can never be HIGH.
"""
from __future__ import annotations

from app.schemas.report import Finding, RiskAssessment, RiskContribution

SEVERITY_POINTS = {"info": 0, "low": 5, "medium": 12, "high": 25, "critical": 40}
CONFIDENCE_FACTOR = {"low": 0.5, "medium": 0.75, "high": 1.0}
MITIGATION_POINTS = 10  # per high-confidence mitigating finding (e.g. aligned DMARC pass)
DIMENSION = {
    "content": "content", "ml": "content",
    "identity": "sender_identity", "header": "sender_identity",
    "authentication": "authentication", "routing": "routing",
    "url": "links", "domain": "infrastructure", "ip": "infrastructure",
    "threat_intel": "threat_intelligence", "attachment": "attachments", "correlation": "correlation",
}
LEVELS = [(70, "CRITICAL"), (45, "HIGH"), (20, "MEDIUM"), (0, "LOW")]
ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _cap(level: str, max_level: str) -> str:
    return level if ORDER.index(level) <= ORDER.index(max_level) else max_level


def classify(level: str, threat: dict, findings: list[Finding]) -> tuple[str, list[str]]:
    ml = threat.get("ml") or {}
    ml_cat, ml_p = ml.get("predicted_category"), ml.get("probability") or 0
    rule_cat = threat.get("rule_category")
    cats = {f.category for f in findings if f.severity not in ("info",)}
    why = [f"Rule-based content category: {rule_cat or 'none'}", f"ML prediction: {ml_cat} (p={ml_p:.2f})" if ml_cat else "ML prediction unavailable"]
    if level == "LOW":
        why.append("Overall risk is LOW, so no threat category is assigned")
        return "legitimate", why
    identity_auth = bool(cats & {"identity", "authentication"})
    if rule_cat and rule_cat == ml_cat:
        why.append("Rules and ML agree")
        return rule_cat, why
    if rule_cat in ("phishing", "bec"):
        why.append(f"Rule evidence for {rule_cat} takes precedence over a disagreeing ML prediction")
        return rule_cat, why
    if ml_cat and ml_cat != "legitimate" and ml_p >= 0.6:
        why.append("ML prediction is confident and not contradicted by rules")
        return ml_cat, why
    if identity_auth and not rule_cat:
        why.append("Sender identity/authentication evidence without a content lure suggests spoofing")
        return "spoofing", why
    why.append("Risk indicators present but no single category is well supported")
    return rule_cat or "suspicious", why


def assess_risk(findings: list[Finding], threat: dict, header: dict, provider_stats: dict) -> RiskAssessment:
    contributions: list[RiskContribution] = []
    mitigation = 0.0
    dims: set[str] = set()
    has_high = False
    for f in findings:
        if f.category == "mitigating":
            if f.confidence == "high":
                mitigation += MITIGATION_POINTS
            elif f.confidence == "medium":
                mitigation += MITIGATION_POINTS / 2
            continue
        pts = SEVERITY_POINTS[f.severity] * CONFIDENCE_FACTOR[f.confidence]
        if pts <= 0:
            continue
        dim = DIMENSION.get(f.category, f.category)
        dims.add(dim)
        has_high = has_high or f.severity in ("high", "critical")
        contributions.append(RiskContribution(finding_id=f.finding_id, title=f.title, category=f.category, dimension=dim,
                                              severity=f.severity, confidence=f.confidence, points=round(pts, 2)))
    raw = sum(c.points for c in contributions)
    score = max(0.0, min(100.0, raw - mitigation))
    level = next(lv for threshold, lv in LEVELS if score >= threshold)
    caps = []
    if len(dims) <= 1 and ORDER.index(level) > ORDER.index("MEDIUM"):
        caps.append(f"Only one evidence dimension ({', '.join(dims)}): capped at MEDIUM")
        level = "MEDIUM"
    elif len(dims) == 2 and level == "CRITICAL":
        caps.append("Only two evidence dimensions: capped at HIGH")
        level = "HIGH"
    if level == "CRITICAL" and not has_high:
        caps.append("No high-severity finding: capped at HIGH")
        level = "HIGH"

    # ---- confidence: how well supported is this assessment?
    factors, points = [], 0
    if len(dims) >= 3:
        points += 2
        factors.append(f"{len(dims)} independent evidence dimensions agree (+2)")
    elif len(dims) == 2:
        points += 1
        factors.append("2 evidence dimensions (+1)")
    auth = header.get("authentication", {})
    definitive = [m for m in ("spf", "dkim", "dmarc") if auth.get(m, {}).get("status") in ("pass", "fail", "softfail")]
    if len(definitive) >= 2:
        points += 1
        factors.append(f"Definitive authentication results for {', '.join(definitive)} (+1)")
    ml = threat.get("ml") or {}
    classification, rationale = classify(level, threat, findings)
    if ml.get("predicted_category") == classification and (ml.get("probability") or 0) >= 0.6:
        points += 1
        factors.append("ML classifier agrees with the final classification (+1)")
    total = sum(sum(v.values()) for v in provider_stats.values()) or 0
    ok = sum(v.get("success", 0) + v.get("unknown", 0) for v in provider_stats.values())
    if total and ok / total >= 0.5:
        points += 1
        factors.append(f"{ok}/{total} intelligence lookups returned data (+1)")
    else:
        factors.append(f"Limited external intelligence: {ok}/{total} lookups returned data (+0)")
    if level == "LOW" and mitigation >= MITIGATION_POINTS / 2:
        points += 1
        factors.append("Strong mitigating evidence (aligned authentication pass) (+1)")
    conf = "HIGH" if points >= 4 else "MEDIUM" if points >= 2 else "LOW"

    top = sorted(contributions, key=lambda c: c.points, reverse=True)
    reasons = [f"{c.title} [{c.severity}/{c.confidence}, +{c.points}]" for c in top[:6]]
    if mitigation:
        reasons.append(f"Mitigating evidence (authentication pass) -{mitigation:g}")
    if not reasons:
        reasons.append("No risk-increasing findings")
    return RiskAssessment(
        risk_level=level, risk_score=round(score, 1), confidence=conf, classification=classification,
        classification_rationale=rationale, reasons=reasons, contributions=top, evidence_dimensions=sorted(dims),
        caps_applied=caps, confidence_factors=factors,
        method="score = sum(severity points x confidence factor) - mitigation; levels LOW<20<=MEDIUM<45<=HIGH<70<=CRITICAL; "
               "corroboration caps: 1 dimension<=MEDIUM, 2 dimensions<=HIGH, CRITICAL needs 3+ dimensions and a high-severity finding. "
               "Severity points: low 5, medium 12, high 25, critical 40; confidence factors: low 0.5, medium 0.75, high 1.0.",
    )
