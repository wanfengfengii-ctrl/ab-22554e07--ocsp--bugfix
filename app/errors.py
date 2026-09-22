"""Structured errors shared by the API and the engine."""
from __future__ import annotations


class ApiError(Exception):
    """An error that maps to a structured HTTP/API response."""

    def __init__(self, code: str, message: str, http_status: int = 400, details=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status
        self.details = details

    def body(self) -> dict:
        err = {"code": self.code, "message": self.message}
        if self.details is not None:
            err["details"] = self.details
        return {"error": err}


class ParseError(Exception):
    """A DER object could not be parsed as its declared type."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class ResourceExhausted(Exception):
    """Deterministic exploration limits were exceeded."""
