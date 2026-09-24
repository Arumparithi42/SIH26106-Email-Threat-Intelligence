"""Logging setup. Logs record indicators and statuses - never API keys or email bodies."""
import logging


def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    # httpx logs full request URLs at INFO. IPQS puts the API key in the URL path,
    # so keep httpx/httpcore quiet to avoid leaking keys into logs.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
