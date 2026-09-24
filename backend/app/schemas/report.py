"""The stable AnalysisReport contract (schema_version 1.0).

Other team modules consume this shape. Rules:
- additive changes only within 1.x (new optional fields are fine);
- renaming/removing a field bumps the version to 2.0.

Nested sections that are naturally free-form (e.g. a provider's raw evidence)
are typed as dict; everything the dashboard/report/risk engine rely on is typed.
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

SCHEMA_VERSION = "1.0"

ProviderStatus = Literal["success", "skipped", "unknown", "rate_limited", "unavailable", "error"]
Verdict = Literal["malicious", "suspicious", "no_detections", "unknown"]
Severity = Literal["info", "low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]
EvidenceType = Literal["observed_fact", "analytical_finding", "threat_intel"]
SignalValue = Literal["detected", "not_detected", "unknown"]


class ProviderResult(BaseModel):
    """Normalised output of every external/threat-intel lookup."""

    provider: str
    indicator: str
    indicator_type: Literal["ip", "domain", "url", "feed"]
    status: ProviderStatus
    reason_code: str | None = None  # why status != success, e.g. no_api_key, quota_exhausted, timeout
    verdict: Verdict = "unknown"
    summary: str = ""
    data: dict[str, Any] = Field(default_factory=dict)
    retrieved_at: str | None = None
    cached: bool = False
    error: str | None = None


class Evidence(BaseModel):
    type: EvidenceType
    label: str
    value: Any = None
    source: str = ""


class Finding(BaseModel):
    finding_id: str
    category: str  # content | ml | identity | authentication | routing | header | url | domain | ip | threat_intel | attachment | correlation | mitigating
    severity: Severity
    confidence: Confidence
    title: str
    description: str
    why_it_matters: str = ""
    finding_type: EvidenceType = "analytical_finding"
    evidence: list[Evidence] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    related_indicators: list[str] = Field(default_factory=list)
    source_module: str = ""


class Signal(BaseModel):
    value: SignalValue = "unknown"
    evidence: list[dict[str, Any]] = Field(default_factory=list)


class TimelineEvent(BaseModel):
    timestamp: str | None
    kind: Literal["investigation", "email"]
    stage: str
    event: str
    status: str = "completed"
    detail: str | None = None


class GraphNode(BaseModel):
    id: str
    type: str
    label: str
    data: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    target: str
    relation: str
    data: dict[str, Any] = Field(default_factory=dict)


class Correlation(BaseModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)
    related_analyses: list[dict[str, Any]] = Field(default_factory=list)


class RiskContribution(BaseModel):
    finding_id: str
    title: str
    category: str
    dimension: str
    severity: Severity
    confidence: Confidence
    points: float


class RiskAssessment(BaseModel):
    risk_level: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    risk_score: float
    confidence: Literal["LOW", "MEDIUM", "HIGH"]
    classification: str
    classification_rationale: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    contributions: list[RiskContribution] = Field(default_factory=list)
    evidence_dimensions: list[str] = Field(default_factory=list)
    caps_applied: list[str] = Field(default_factory=list)
    confidence_factors: list[str] = Field(default_factory=list)
    method: str = ""


class Indicators(BaseModel):
    ips: list[dict[str, Any]] = Field(default_factory=list)
    domains: list[dict[str, Any]] = Field(default_factory=list)
    urls: list[dict[str, Any]] = Field(default_factory=list)
    attachments: list[dict[str, Any]] = Field(default_factory=list)
    email_addresses: list[dict[str, Any]] = Field(default_factory=list)


class AnalysisReport(BaseModel):
    schema_version: str = SCHEMA_VERSION
    analysis_id: str
    created_at: str
    input: dict[str, Any]
    email: dict[str, Any]
    threat_detection: dict[str, Any]
    header_forensics: dict[str, Any]
    indicators: Indicators
    ip_intelligence: list[dict[str, Any]]
    domain_intelligence: list[dict[str, Any]]
    url_analysis: list[dict[str, Any]]
    attachment_analysis: list[dict[str, Any]]
    correlation: Correlation
    findings: list[Finding]
    risk_assessment: RiskAssessment
    timeline: list[TimelineEvent]
    provider_status: dict[str, Any]
    report: dict[str, Any]
    limitations: list[str]
