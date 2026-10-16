"""WSGI request and response primitives: strict JSON, bounded bodies, safe headers."""

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from http.cookies import CookieError, SimpleCookie
from typing import Any
from urllib.parse import parse_qsl

from app.api.errors import ApiError, bad_request

MAX_BODY_BYTES = 64 * 1024
MAX_QUERY_LENGTH = 2048
MAX_PATH_LENGTH = 512
JSON_TYPE = "application/json"

# Sent on every response. The API serves JSON only, so nothing may be framed, sniffed,
# cached, or used as a document.
SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("Cache-Control", "no-store"),
    ("Pragma", "no-cache"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"),
    ("Referrer-Policy", "no-referrer"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
)

_STATUS_TEXT = {
    200: "OK", 201: "Created", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
    405: "Method Not Allowed", 409: "Conflict", 411: "Length Required", 413: "Content Too Large", 415: "Unsupported Media Type",
    422: "Unprocessable Content", 500: "Internal Server Error", 503: "Service Unavailable",
}


@dataclass
class Request:
    method: str
    path: str
    query: dict[str, str]
    headers: dict[str, str]  # lower-case names
    cookies: dict[str, str]
    body: dict[str, Any] | None
    request_id: str
    path_params: dict[str, str] = field(default_factory=dict)

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


@dataclass
class Response:
    status: int
    body: dict[str, Any]
    headers: list[tuple[str, str]] = field(default_factory=list)

    def encode(self, request_id: str) -> tuple[str, list[tuple[str, str]], bytes]:
        payload = json.dumps(self.body, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
        headers = [
            ("Content-Type", f"{JSON_TYPE}; charset=utf-8"),
            ("Content-Length", str(len(payload))),
            ("X-Request-Id", request_id),
            *SECURITY_HEADERS,
            *self.headers,
        ]
        return f"{self.status} {_STATUS_TEXT.get(self.status, 'Unknown')}", headers, payload


def read_headers(environ: Mapping[str, Any]) -> dict[str, str]:
    headers = {}
    for key, value in environ.items():
        if key.startswith("HTTP_"):
            headers[key[5:].replace("_", "-").lower()] = str(value)
    if environ.get("CONTENT_TYPE"):
        headers["content-type"] = str(environ["CONTENT_TYPE"])
    if environ.get("CONTENT_LENGTH"):
        headers["content-length"] = str(environ["CONTENT_LENGTH"])
    return headers


def read_query(environ: Mapping[str, Any]) -> dict[str, str]:
    raw = str(environ.get("QUERY_STRING") or "")
    if len(raw) > MAX_QUERY_LENGTH:
        raise bad_request("The query string is too long.")
    try:
        pairs = parse_qsl(raw, keep_blank_values=True, strict_parsing=bool(raw), max_num_fields=20)
    except ValueError:
        raise bad_request("The query string is malformed.") from None
    query: dict[str, str] = {}
    for key, value in pairs:
        if key in query:
            raise bad_request(f"Query parameter {key[:40]!r} is repeated.")
        query[key] = value
    return query


def read_cookies(headers: Mapping[str, str]) -> dict[str, str]:
    raw = headers.get("cookie")
    if not raw:
        return {}
    jar = SimpleCookie()
    try:
        jar.load(raw)
    except CookieError:
        return {}  # an unparseable cookie header authenticates nothing
    return {name: morsel.value for name, morsel in jar.items()}


def read_json_body(environ: Mapping[str, Any], headers: Mapping[str, str]) -> dict[str, Any]:
    """A JSON object, or an ApiError. Only ``application/json`` is accepted (CSRF hardening:
    a cross-site HTML form cannot send it without a CORS preflight, which OGWA never grants)."""
    content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != JSON_TYPE:
        raise ApiError(415, "UNSUPPORTED_MEDIA_TYPE", "Send the request body as application/json.")
    try:
        length = int(headers.get("content-length", ""))
    except ValueError:
        raise ApiError(411, "LENGTH_REQUIRED", "A Content-Length header is required.") from None
    if length < 0:
        raise bad_request("Content-Length is invalid.")
    if length > MAX_BODY_BYTES:
        raise ApiError(413, "PAYLOAD_TOO_LARGE", f"The request body is limited to {MAX_BODY_BYTES} bytes.")
    raw = environ["wsgi.input"].read(length) if length else b""
    try:
        body = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates, parse_constant=_no_constants)
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateKey, ValueError):
        raise bad_request("The request body is not a valid JSON object.") from None
    if not isinstance(body, dict):
        raise bad_request("The request body must be a JSON object.")
    return body


class _DuplicateKey(ValueError):
    pass


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


def _no_constants(name: str) -> None:
    raise ValueError(f"{name} is not valid JSON")


def session_cookie(name: str, value: str, max_age: int | None = None) -> tuple[str, str]:
    # __Host- cookies must be Secure, Path=/, and carry no Domain. Browsers treat
    # http://127.0.0.1 and http://localhost as secure contexts, so local development works.
    expiry = f"; Max-Age={max_age}" if max_age else ""
    return ("Set-Cookie", f"{name}={value}; Path=/; Secure; HttpOnly; SameSite=Strict{expiry}")


def expired_cookie(name: str) -> tuple[str, str]:
    return ("Set-Cookie", f"{name}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0")
