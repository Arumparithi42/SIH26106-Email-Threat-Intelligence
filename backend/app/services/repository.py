"""Persistence of AnalysisReports (full JSON + normalised rows)."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import select

from app.database.db import session_scope
from app.database import models as m


def save_report(r: dict) -> None:
    aid = r["analysis_id"]
    h = r["email"]["headers"]
    risk = r["risk_assessment"]
    with session_scope() as s:
        s.add(m.Analysis(
            analysis_id=aid, created_at=datetime.fromisoformat(r["created_at"].replace("Z", "+00:00")), filename=r["input"].get("filename"),
            input_sha256=r["input"]["sha256"], subject=h.get("subject"), from_address=(h.get("from") or {}).get("address"),
            classification=risk["classification"], risk_level=risk["risk_level"], risk_score=risk["risk_score"], confidence=risk["confidence"],
            schema_version=r["schema_version"], report_json=r))
        s.flush()
        s.add(m.EmailRecord(analysis_id=aid, message_id=h.get("message_id"), from_address=(h.get("from") or {}).get("address"),
                            to_addresses=[a["address"] for a in h.get("to") or []], subject=h.get("subject"), date=h.get("date_iso"),
                            body_excerpt=(r["email"].get("body_text") or "")[:1000]))
        for kind in ("ips", "domains", "urls", "email_addresses", "attachments"):
            for i in r["indicators"][kind]:
                s.add(m.IndicatorRecord(analysis_id=aid, indicator_id=i["id"], indicator_type=i["id"].split(":", 1)[0], value=i["value"], roles=i["roles"]))
        for f in r["findings"]:
            s.add(m.FindingRecord(analysis_id=aid, finding_id=f["finding_id"], category=f["category"], severity=f["severity"],
                                  confidence=f["confidence"], title=f["title"], data=f))
        for ip in r["ip_intelligence"]:
            s.add(m.IPIntelRecord(analysis_id=aid, ip=ip["ip"], data=ip))
        for d in r["domain_intelligence"]:
            s.add(m.DomainIntelRecord(analysis_id=aid, domain=d["domain"], data=d))
        for u in r["url_analysis"]:
            s.add(m.URLRecord(analysis_id=aid, url=u["url"], domain=u.get("domain"), data=u))
        for a in r["attachment_analysis"]:
            s.add(m.AttachmentRecord(analysis_id=aid, filename=a["filename"], sha256=a["sha256"], data=a))
        for n in r["correlation"]["nodes"]:
            s.add(m.GraphNodeRecord(analysis_id=aid, node_id=n["id"], node_type=n["type"], label=n["label"], data=n["data"]))
        for e in r["correlation"]["edges"]:
            s.add(m.GraphEdgeRecord(analysis_id=aid, source=e["source"], target=e["target"], relation=e["relation"]))
        for t in r["timeline"]:
            s.add(m.TimelineEventRecord(analysis_id=aid, timestamp=t["timestamp"] or "", kind=t["kind"], stage=t["stage"],
                                        event=t["event"], status=t["status"], detail=t.get("detail")))


def get_report(analysis_id: str) -> dict | None:
    with session_scope() as s:
        row = s.get(m.Analysis, analysis_id)
        return row.report_json if row else None


def list_analyses(limit: int = 50) -> list[dict]:
    with session_scope() as s:
        rows = s.execute(select(m.Analysis).order_by(m.Analysis.created_at.desc()).limit(limit)).scalars().all()
        return [{"analysis_id": r.analysis_id, "created_at": r.created_at.isoformat(), "filename": r.filename, "subject": r.subject,
                 "from_address": r.from_address, "classification": r.classification, "risk_level": r.risk_level,
                 "risk_score": r.risk_score, "confidence": r.confidence} for r in rows]
