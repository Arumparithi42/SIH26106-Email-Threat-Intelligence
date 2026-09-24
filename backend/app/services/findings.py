"""Helper to build Finding objects consistently across modules."""
from __future__ import annotations

from typing import Any

from app.schemas.report import Evidence, Finding


def ev(label: str, value: Any, source: str = "", type_: str = "observed_fact") -> Evidence:
    return Evidence(type=type_, label=label, value=value, source=source)


def finding(
    finding_id: str,
    *,
    category: str,
    severity: str,
    confidence: str,
    title: str,
    description: str,
    why: str = "",
    evidence: list[Evidence] | None = None,
    sources: list[str] | None = None,
    related: list[str] | None = None,
    module: str = "",
    finding_type: str = "analytical_finding",
) -> Finding:
    return Finding(
        finding_id=finding_id,
        category=category,
        severity=severity,
        confidence=confidence,
        title=title,
        description=description,
        why_it_matters=why,
        finding_type=finding_type,
        evidence=evidence or [],
        sources=sources or [],
        related_indicators=related or [],
        source_module=module,
    )
