"""Scrubbing of credentials from text destined for logs, diagnostics, or reports."""

import re
import threading

REDACTED = "***"

# Shorter values are too likely to collide with ordinary text to scrub verbatim.
_MIN_REGISTERED_SECRET_LENGTH = 8

_known_secrets: set[str] = set()
_known_secrets_lock = threading.Lock()

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Authorization schemes: "SSWS <token>", "Bearer <token>", "Basic <creds>".
    (re.compile(r"(?i)\b(SSWS|Bearer|Basic)\s+[^\s,;\"']+"), rf"\1 {REDACTED}"),
    # key=value / key: value / "key": "value" where the key names a credential.
    (
        re.compile(
            r"(?i)\b([\w.-]*(?:password|passwd|secret|token|api[_-]?key|authorization|cookie)[\w.-]*)"
            r"([\"']?\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s&,;]+)"
        ),
        rf"\1\2{REDACTED}",
    ),
    # Userinfo embedded in URLs: scheme://user:pass@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@"), rf"\1{REDACTED}@"),
)

SENSITIVE_KEY = re.compile(r"(?i)password|passwd|secret|token|api[_-]?key|authorization|cookie")


def register_secret(value: str) -> None:
    """Remember a secret value so it is scrubbed verbatim wherever it appears."""
    if isinstance(value, str) and len(value) >= _MIN_REGISTERED_SECRET_LENGTH:
        with _known_secrets_lock:
            _known_secrets.add(value)


def redact_text(text: str) -> str:
    with _known_secrets_lock:
        known = sorted(_known_secrets, key=len, reverse=True)
    for value in known:
        if value in text:
            text = text.replace(value, REDACTED)
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text
