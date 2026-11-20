"""Structured (JSON) logging with a per-request id. Standard library only.

Privacy: log records carry the request path and status, never query strings, headers, bodies or tokens
(several endpoints carry secrets or scanned content in the query string, e.g. reward callbacks and QR verification).
"""
import contextvars
import json
import logging
import re
from datetime import datetime, timezone

request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")
_QUERY = re.compile(r"\?[^\s\"']*")
_BEARER = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+")


class RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get()
        return True


def scrub(text: str) -> str:
    """Remove query strings and bearer tokens from any text headed for the logs."""
    return _BEARER.sub(r"\1[redacted]", _QUERY.sub("?[query removed]", text))


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        data = {"time": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="milliseconds"),
                "level": record.levelname, "logger": record.name, "request_id": getattr(record, "request_id", "-"),
                "message": scrub(record.getMessage())}
        if record.exc_info:
            data["exception"] = scrub(self.formatException(record.exc_info))[:4000]
        return json.dumps(data, ensure_ascii=False)


def build_logging(level: str = "INFO", fmt: str = "text") -> dict:
    return {
        "version": 1, "disable_existing_loggers": False,
        "filters": {"request_id": {"()": "config.logging_utils.RequestIdFilter"}},
        "formatters": {"json": {"()": "config.logging_utils.JsonFormatter"},
                       "text": {"format": "%(asctime)s %(levelname)s [%(request_id)s] %(name)s: %(message)s"}},
        "handlers": {"console": {"class": "logging.StreamHandler", "filters": ["request_id"],
                                 "formatter": "json" if fmt == "json" else "text"}},
        "root": {"handlers": ["console"], "level": level},
    }
