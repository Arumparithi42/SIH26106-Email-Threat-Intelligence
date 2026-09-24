"""REST API. The React dashboard (and other team modules) use only these endpoints."""
from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, Response

from app.core.config import get_settings
from app.services import repository
from app.services.email_parser.parser import EmailParseError
from app.services.pipeline import analyze_email
from app.services.reporting.pdf_report import build_pdf
from app.services.threat_detection import ml

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api")


@router.get("/health")
def health() -> dict:
    s = get_settings()
    info = ml.model_info()
    return {"status": "ok", "providers": s.provider_configuration(), "max_upload_mb": s.max_upload_mb,
            "ml_model": {"model": info["model"], "classes": info["classes"], "cv_macro_f1": info["metrics"]["macro_f1"]}}


@router.get("/model")
def model() -> dict:
    return ml.model_info()


@router.post("/analyze/email")
def analyze(file: UploadFile | None = File(default=None), raw_email: str | None = Form(default=None)) -> dict:
    limit = get_settings().max_upload_mb * 1024 * 1024
    if file is not None:
        data = file.file.read(limit + 1)
        name = Path(file.filename or "upload.eml").name
    elif raw_email:
        data = raw_email.encode("utf-8", "replace")
        name = None
    else:
        raise HTTPException(400, "Provide an .eml file (field 'file') or raw email text (field 'raw_email').")
    if len(data) > limit:
        raise HTTPException(413, f"Email larger than {get_settings().max_upload_mb} MB")
    try:
        return analyze_email(data, name)
    except EmailParseError as exc:
        raise HTTPException(422, str(exc)) from exc


@router.get("/analyses")
def analyses(limit: int = 50) -> list[dict]:
    return repository.list_analyses(min(max(limit, 1), 200))


def _report_or_404(analysis_id: str) -> dict:
    r = repository.get_report(analysis_id)
    if r is None:
        raise HTTPException(404, "Analysis not found")
    return r


@router.get("/analysis/{analysis_id}")
def get_analysis(analysis_id: str) -> dict:
    return _report_or_404(analysis_id)


@router.get("/analysis/{analysis_id}/graph")
def get_graph(analysis_id: str) -> dict:
    return _report_or_404(analysis_id)["correlation"]


@router.get("/analysis/{analysis_id}/timeline")
def get_timeline(analysis_id: str) -> list[dict]:
    return _report_or_404(analysis_id)["timeline"]


@router.get("/analysis/{analysis_id}/report")
def get_pdf(analysis_id: str):
    report = _report_or_404(analysis_id)
    path = Path(get_settings().reports_dir) / f"{analysis_id}.pdf"
    headers = {"Content-Disposition": f'attachment; filename="forensic-report-{analysis_id}.pdf"'}
    if path.is_file():
        return FileResponse(path, media_type="application/pdf", headers=headers)
    return Response(build_pdf(report), media_type="application/pdf", headers=headers)
