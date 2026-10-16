"""API test helpers: an in-process WSGI client over a seeded SYNTHETIC store.

No sockets: requests are WSGI environ dicts handed straight to the application. Every
identity is a synthetic principal from config/synthetic-idp.json.
"""

import io
import json
import logging
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Any

from app.api.local import build_local_api
from app.api.sessions import CSRF_HEADER, SESSION_COOKIE
from app.core.logging_setup import RedactingJsonFormatter
from app.demo.synthetic_world import AS_OF, COLLECTOR, HOUR, create_seeded_store
from tests.store_fixtures import memory_target

VIEWER = "synthetic.viewer.one"
AUTOMATION = "synthetic.automation.one"
AUTOMATION_2 = "synthetic.automation.two"
SECURITY = "synthetic.securityiam.one"
SECURITY_2 = "synthetic.securityiam.two"
EXECUTOR = "synthetic.executor.one"
ADMIN = "synthetic.admin.one"
DUAL = "synthetic.dualrole.one"  # IDENTITY_AUTOMATION + SECURITY_IAM (D49)
APPROVER_EXECUTOR = "synthetic.approverexec.one"  # SECURITY_IAM + EXECUTOR
LOOKALIKE = "synthetic.lookalike.one"  # in a group whose display name matches SECURITY_IAM's, but not its id
NO_ROLE = "synthetic.norole.one"

ALL_PRINCIPALS = (VIEWER, AUTOMATION, AUTOMATION_2, SECURITY, SECURITY_2, EXECUTOR, ADMIN, DUAL, APPROVER_EXECUTOR,
                  LOOKALIKE, NO_ROLE)


@dataclass
class Result:
    status: int
    headers: dict[str, list[str]]
    json: dict[str, Any]

    def header(self, name: str) -> str | None:
        values = self.headers.get(name.lower())
        return values[0] if values else None

    @property
    def code(self) -> str | None:
        return self.json.get("error", {}).get("code")


class ApiClient:
    def __init__(self, api) -> None:
        self.api = api
        self.cookie: str | None = None
        self.csrf: str | None = None

    def request(self, method: str, path: str, body: Any = None, *, headers: dict[str, str] | None = None,
                csrf: bool = True, raw: bytes | None = None, content_type: str | None = "application/json") -> Result:
        path, _, query = path.partition("?")
        payload = raw if raw is not None else (b"" if body is None else json.dumps(body).encode())
        environ: dict[str, Any] = {
            "REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": query, "SERVER_NAME": "127.0.0.1",
            "SERVER_PORT": "8765", "wsgi.input": io.BytesIO(payload), "wsgi.url_scheme": "http",
        }
        if method == "POST":
            if content_type is not None:
                environ["CONTENT_TYPE"] = content_type
            environ["CONTENT_LENGTH"] = str(len(payload))
        if self.cookie:
            environ["HTTP_COOKIE"] = f"{SESSION_COOKIE}={self.cookie}"
        if method == "POST" and csrf and self.csrf:
            environ["HTTP_" + CSRF_HEADER.upper().replace("-", "_")] = self.csrf
        for name, value in (headers or {}).items():
            environ["HTTP_" + name.upper().replace("-", "_")] = value
        captured: dict[str, Any] = {}

        def start_response(status, response_headers):
            captured["status"] = int(status.split(" ", 1)[0])
            captured["headers"] = response_headers

        chunks = self.api(environ, start_response)
        grouped: dict[str, list[str]] = {}
        for name, value in captured["headers"]:
            grouped.setdefault(name.lower(), []).append(value)
        return Result(captured["status"], grouped, json.loads(b"".join(chunks).decode("utf-8")))

    def get(self, path: str, **kw) -> Result:
        return self.request("GET", path, **kw)

    def post(self, path: str, body: Any = None, **kw) -> Result:
        return self.request("POST", path, {} if body is None else body, **kw)

    def sign_in(self, subject: str) -> Result:
        result = self.post("/api/v1/session", {"subject": subject})
        if result.status == 201:
            cookie = result.header("set-cookie")
            self.cookie = cookie.split(";", 1)[0].split("=", 1)[1]
            self.csrf = result.json["csrfToken"]
        return result


class CapturingHandler(logging.Handler):
    """Keeps every API log line, formatted exactly as production would write it."""

    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.setFormatter(RedactingJsonFormatter())
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(self.format(record))


class TickClock:
    """Like the seed clock (one second per reading), but a test can also jump it forward."""

    def __init__(self, start: datetime = AS_OF + HOUR) -> None:
        self.now = start

    def __call__(self) -> datetime:
        value = self.now
        self.now += timedelta(seconds=1)
        return value

    def advance(self, delta: timedelta) -> None:
        self.now += delta


class World:
    """A freshly seeded synthetic world and an API over it, sharing one deterministic clock."""

    _loggers = 0

    def __init__(self, *, mapping_gateway=None, synthetic_directory: bool = True, dataset: str = "classic") -> None:
        if dataset == "null-meridian":
            from app.demo.null_meridian.profile import AS_OF as NM_AS_OF
            from app.demo.null_meridian.world import create_null_meridian_store

            self.clock = TickClock(NM_AS_OF + HOUR)
            self.store, self.summary = create_null_meridian_store(memory_target(), clock=self.clock)
        else:
            self.clock = TickClock()
            self.store, self.summary = create_seeded_store(memory_target(), clock=self.clock)
        World._loggers += 1
        self.log = CapturingHandler()
        logger = logging.getLogger(f"ogwa.test.api.{World._loggers}")
        logger.propagate = False
        logger.setLevel(logging.DEBUG)
        logger.addHandler(self.log)
        self.api = build_local_api(self.store, clock=self.clock, mapping_gateway=mapping_gateway,
                                   synthetic_directory=synthetic_directory, logger=logger)
        self.scenarios = {s.key: s for s in self.summary.scenarios}

    def refresh_evidence(self, candidate_id: str) -> None:
        """Re-observe the candidate's evidence now, with unchanged facts (so its fingerprint is unchanged)."""
        candidate = self.store.load_candidate(candidate_id)
        for record in self.store.evidence_bundle(candidate).records():
            fresh = replace(record, provenance=replace(record.provenance, observed_at=self.clock()))
            self.store.record_evidence(fresh, actor=COLLECTOR)

    def candidate(self, key: str) -> str:
        return self.scenarios[key].candidate_id

    def client(self, subject: str | None = None) -> ApiClient:
        client = ApiClient(self.api)
        if subject is not None:
            result = client.sign_in(subject)
            assert result.status == 201, result.json
        return client

    def fingerprint(self, client: ApiClient, candidate_id: str) -> str:
        result = client.get(f"/api/v1/candidates/{candidate_id}")
        assert result.status == 200, result.json
        return result.json["evidenceFingerprint"]

    def close(self) -> None:
        self.store.close()
