"""Database tables.

`analyses.report_json` holds the complete AnalysisReport (the stable contract).
The other per-analysis tables hold normalised copies of the same data so that
other team modules / SQL queries can search across analyses (e.g. "which emails
used this IP?") without parsing JSON.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database.db import Base


def _fk() -> Mapped[str]:
    return mapped_column(String(64), ForeignKey("analyses.analysis_id", ondelete="CASCADE"), index=True)


class Analysis(Base):
    __tablename__ = "analyses"
    analysis_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    filename: Mapped[str | None] = mapped_column(String(255))
    input_sha256: Mapped[str] = mapped_column(String(64), index=True)
    subject: Mapped[str | None] = mapped_column(Text)
    from_address: Mapped[str | None] = mapped_column(String(320))
    classification: Mapped[str | None] = mapped_column(String(32))
    risk_level: Mapped[str | None] = mapped_column(String(16))
    risk_score: Mapped[float | None] = mapped_column(Float)
    confidence: Mapped[str | None] = mapped_column(String(16))
    schema_version: Mapped[str] = mapped_column(String(16))
    report_json: Mapped[dict] = mapped_column(JSON)


class EmailRecord(Base):
    __tablename__ = "emails"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_id: Mapped[str] = _fk()
    message_id: Mapped[str | None] = mapped_column(Text)
    from_address: Mapped[str | None] = mapped_column(String(320), index=True)
    to_addresses: Mapped[list] = mapped_column(JSON)
    subject: Mapped[str | None] = mapped_column(Text)
    date: Mapped[str | None] = mapped_column(String(64))
    body_excerpt: Mapped[str | None] = mapped_column(Text)


class IndicatorRecord(Base):
    __tablename__ = "indicators"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_id: Mapped[str] = _fk()
    indicator_id: Mapped[str] = mapped_column(String(512), index=True)
    indicator_type: Mapped[str] = mapped_column(String(32))
    value: Mapped[str] = mapped_column(Text)
    roles: Mapped[list] = mapped_column(JSON)


class FindingRecord(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_id: Mapped[str] = _fk()
    finding_id: Mapped[str] = mapped_column(String(64))
    category: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(Text)
    data: Mapped[dict] = mapped_column(JSON)


class IPIntelRecord(Base):
    __tablename__ = "ip_intelligence"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_id: Mapped[str] = _fk()
    ip: Mapped[str] = mapped_column(String(64), index=True)
    data: Mapped[dict] = mapped_column(JSON)


class DomainIntelRecord(Base):
    __tablename__ = "domain_intelligence"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_id: Mapped[str] = _fk()
    domain: Mapped[str] = mapped_column(String(255), index=True)
    data: Mapped[dict] = mapped_column(JSON)


class URLRecord(Base):
    __tablename__ = "urls"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_id: Mapped[str] = _fk()
    url: Mapped[str] = mapped_column(Text)
    domain: Mapped[str | None] = mapped_column(String(255), index=True)
    data: Mapped[dict] = mapped_column(JSON)


class AttachmentRecord(Base):
    __tablename__ = "attachments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_id: Mapped[str] = _fk()
    filename: Mapped[str | None] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    data: Mapped[dict] = mapped_column(JSON)


class GraphNodeRecord(Base):
    __tablename__ = "graph_nodes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_id: Mapped[str] = _fk()
    node_id: Mapped[str] = mapped_column(String(512), index=True)
    node_type: Mapped[str] = mapped_column(String(32))
    label: Mapped[str] = mapped_column(Text)
    data: Mapped[dict] = mapped_column(JSON)


class GraphEdgeRecord(Base):
    __tablename__ = "graph_edges"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_id: Mapped[str] = _fk()
    source: Mapped[str] = mapped_column(String(512))
    target: Mapped[str] = mapped_column(String(512))
    relation: Mapped[str] = mapped_column(String(64))


class TimelineEventRecord(Base):
    __tablename__ = "timeline_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_id: Mapped[str] = _fk()
    timestamp: Mapped[str] = mapped_column(String(40))
    kind: Mapped[str] = mapped_column(String(32))
    stage: Mapped[str] = mapped_column(String(64))
    event: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32))
    detail: Mapped[str | None] = mapped_column(Text)


class ProviderCache(Base):
    __tablename__ = "provider_cache"
    __table_args__ = (UniqueConstraint("provider", "indicator_type", "indicator", "variant"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider: Mapped[str] = mapped_column(String(64))
    indicator_type: Mapped[str] = mapped_column(String(32))
    indicator: Mapped[str] = mapped_column(Text)
    variant: Mapped[str] = mapped_column(String(64), default="")
    status: Mapped[str] = mapped_column(String(32))
    response_json: Mapped[dict] = mapped_column(JSON)
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class ProviderState(Base):
    """Remembers 'quota exhausted' across restarts so we stop wasting calls."""

    __tablename__ = "provider_state"
    provider: Mapped[str] = mapped_column(String(64), primary_key=True)
    blocked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reason_code: Mapped[str | None] = mapped_column(String(64))
    last_message: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
