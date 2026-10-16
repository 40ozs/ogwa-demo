"""Structured API errors.

Every failure leaves the API as ``{"error": {"code", "message", "requestId", ...}}``. The
code is a stable machine-readable name; the message is written for an operator and never
carries exception text, stack traces, or credentials. Unexpected exceptions become a
generic ``INTERNAL_ERROR`` and are logged (redacted) server-side only.
"""

from collections.abc import Iterable

from app.core.redaction import redact_text

MAX_PROBLEMS = 50
MAX_PROBLEM_LENGTH = 500


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, *, problems: Iterable[str] = (),
                 headers: Iterable[tuple[str, str]] = ()) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = redact_text(message)
        self.problems = tuple(redact_text(str(p))[:MAX_PROBLEM_LENGTH] for p in problems)[:MAX_PROBLEMS]
        self.headers = tuple(headers)
        self.subject: str | None = None  # the refused principal, for the security log only
        self.audit_event_id: str | None = None  # set when the refusal was chained (GOVERNED_REQUEST_REFUSED)

    def body(self, request_id: str) -> dict:
        error = {"code": self.code, "message": self.message, "requestId": request_id}
        if self.problems:
            error["problems"] = list(self.problems)
        if self.audit_event_id:
            error["auditEventId"] = self.audit_event_id
        return {"error": error}


def bad_request(message: str) -> ApiError:
    return ApiError(400, "MALFORMED_REQUEST", message)


def validation(message: str) -> ApiError:
    return ApiError(422, "VALIDATION_FAILED", message)


def unauthenticated(message: str = "Sign in to use this endpoint.") -> ApiError:
    return ApiError(401, "UNAUTHENTICATED", message)


def forbidden(message: str = "Your roles do not permit this operation.", code: str = "FORBIDDEN") -> ApiError:
    return ApiError(403, code, message)


def not_found(what: str = "resource") -> ApiError:
    return ApiError(404, "NOT_FOUND", f"No such {what}.")


def conflict(code: str, message: str, problems: Iterable[str] = ()) -> ApiError:
    return ApiError(409, code, message, problems=problems)


INTERNAL_ERROR = ApiError(500, "INTERNAL_ERROR", "The request failed. Quote the request id when reporting it.")
