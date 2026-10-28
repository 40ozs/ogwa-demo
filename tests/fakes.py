"""Test doubles and synthetic fixtures. Nothing here contacts a real system."""

import contextlib
import io
import logging

from app.core.logging_setup import RedactingJsonFormatter

# Synthetic values only. ".example" hosts are reserved (RFC 2606) and never resolve to a real tenant.
SYNTHETIC_OKTA_URL = "https://okta.synthetic.example"
SYNTHETIC_OKTA_HOST = "okta.synthetic.example"
SYNTHETIC_OKTA_TOKEN = "synthetic-okta-token-value-0001"
SYNTHETIC_AAP_URL = "https://aap.synthetic.example"
SYNTHETIC_AAP_TOKEN = "synthetic-aap-token-value-0002"


def read_only_env(**overrides: str) -> dict[str, str]:
    env = {
        "OGWA_EXECUTION_MODE": "READ_ONLY_PRODUCTION",
        "OGWA_OKTA_ORG_URL": SYNTHETIC_OKTA_URL,
        "OGWA_OKTA_API_TOKEN": SYNTHETIC_OKTA_TOKEN,
        "OGWA_AAP_URL": SYNTHETIC_AAP_URL,
        "OGWA_AAP_TOKEN": SYNTHETIC_AAP_TOKEN,
    }
    env.update(overrides)
    return env


class FakeTransport:
    """Returns queued responses (or raises queued exceptions) and records every call."""

    def __init__(self, *responses):
        self._responses = list(responses)
        self.calls: list[dict] = []

    def send(self, method, url, headers, body, *, connect_timeout, read_timeout, max_response_bytes):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers),
                "body": body,
                "connect_timeout": connect_timeout,
                "read_timeout": read_timeout,
                "max_response_bytes": max_response_bytes,
            }
        )
        if not self._responses:
            raise AssertionError("FakeTransport received more requests than expected")
        item = self._responses.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


class RecordingSleep:
    def __init__(self):
        self.delays: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.delays.append(seconds)


@contextlib.contextmanager
def captured_logs(name: str = "ogwa"):
    logger = logging.getLogger(name)
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(RedactingJsonFormatter())
    saved = (logger.level, logger.propagate)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    try:
        yield stream
    finally:
        logger.removeHandler(handler)
        logger.setLevel(saved[0])
        logger.propagate = saved[1]
