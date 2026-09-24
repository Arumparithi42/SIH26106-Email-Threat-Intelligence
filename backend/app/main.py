"""FastAPI application entry point: `uvicorn app.main:app --reload` (from backend/)."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.core.config import get_settings
from app.core.logging_config import configure_logging
from app.database.db import init_db


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level)
    app = FastAPI(title="SIH26106 Email Threat Intelligence API", version="1.0.0",
                  description="AI-assisted email threat detection, geolocation and forensic investigation.", lifespan=lifespan)
    app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origin_list, allow_methods=["GET", "POST"], allow_headers=["*"])
    app.include_router(router)
    return app


app = create_app()
