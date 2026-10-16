"""The OGWA operator API as a WSGI application.

Request pipeline, in order (each step can only refuse):

1. A server-generated request id (``req_<32 hex>``), returned as ``X-Request-Id`` and used
   as the audit correlation id of every write the request makes.
2. Route match (404/405). Every route declares, at registration, whether it is public,
   needs only a session, or needs one of a set of permissions. There is no default.
3. Authentication from the session cookie only. An ``Authorization`` header is refused,
   and identity headers such as ``X-Remote-User`` are never read.
4. For POST: an Origin check, then the session's CSRF token in ``X-OGWA-CSRF``.
5. The route's static permission. An unauthorized caller is refused here, before
   anything it sent is parsed.
6. Query and body validation: JSON only, bounded size, no duplicate or unknown keys.
7. The handler's own per-action checks (separation of duties, evidence rules).
8. Errors become structured JSON; unexpected exceptions are logged redacted and answered
   with a generic ``INTERNAL_ERROR``.
"""

import logging
import re
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.api.authz import Permission, Principal, RoleBindings
from app.api.errors import INTERNAL_ERROR, ApiError, forbidden, unauthenticated
from app.api.http import (
    MAX_PATH_LENGTH,
    Request,
    Response,
    read_cookies,
    read_headers,
    read_json_body,
    read_query,
    session_cookie,
)
from app.api.identity import IdentityAdapter
from app.api.directory import DirectoryView
from app.api.readmodel import ReadModel
from app.api.remediation import RemediationService
from app.api.services import LifecycleService, MappingReviewGateway, MappingReviews, policy_in_force
from app.api.sessions import CSRF_HEADER, SESSION_COOKIE, Session, SessionManager
from app.api.validation import check_query
from app.core.errors import ConfigError
from app.core.modes import ExecutionMode
from app.domain.ids import IdKind, new_id
from app.domain.quarantine import QuarantineOus
from app.remediation.aap import TemplateMetadata
from app.remediation.allowlist import RemediationAllowlist
from app.store.errors import StoreIntegrityError
from app.store.store import Store

API_PREFIX = "/api/v1"
ALLOWED_METHODS = ("GET", "POST")
# Fetch metadata values that mean "not a cross-site request".
_SAME_SITE_FETCH = frozenset({"same-origin", "none"})
_SEGMENT = re.compile(r"\{([A-Za-z]+)\}")
# Refusals of a valid governed request that are chained (403/409). A refused lifecycle
# transition is already chained by the store as TRANSITION_REFUSED, so it is not doubled.
GOVERNED_REFUSAL_STATUSES = frozenset({403, 409})
CHAINED_ELSEWHERE = frozenset({"TRANSITION_REFUSED"})
# Request fields worth keeping with a chained refusal. Free text (reasons) is not kept. A
# remediation's "target" is an object; its one id field is kept as request.target.<name>.
_GOVERNED_DETAIL_FIELDS = ("target", "stage", "decision", "kind", "dryRun", "executionMode", "approvalId", "jobId",
                           "objectGuid", "searchId", "operation")


@dataclass(frozen=True)
class Route:
    method: str
    pattern: str
    handler: Callable[["Context"], Response]
    access: str  # "public", "session", or "permission"
    any_of: frozenset[Permission] = frozenset()
    query: frozenset[str] = frozenset()
    # For a route that changes governed state: the path parameter naming its subject. A
    # refusal of a valid request on such a route is chained as GOVERNED_REQUEST_REFUSED.
    governed_subject: str | None = None
    regex: re.Pattern[str] = field(init=False, compare=False)

    def __post_init__(self) -> None:
        if self.method not in ALLOWED_METHODS:
            raise ValueError(f"unsupported method {self.method}")
        if self.access not in ("public", "session", "permission"):
            raise ValueError(f"route {self.pattern} has no declared access")
        if (self.access == "permission") != bool(self.any_of):
            raise ValueError(f"route {self.pattern}: permission routes, and only they, name permissions")
        if not self.pattern.startswith(API_PREFIX + "/"):
            raise ValueError(f"route {self.pattern} is outside {API_PREFIX}")
        if self.governed_subject is not None and (
                self.method != "POST" or self.access == "public" or "{" + self.governed_subject + "}" not in self.pattern):
            raise ValueError(f"route {self.pattern}: a governed route is an authenticated POST naming its subject")
        body = _SEGMENT.sub(lambda m: f"(?P<{m[1]}>[^/]+)", re.escape(self.pattern).replace(r"\{", "{").replace(r"\}", "}"))
        object.__setattr__(self, "regex", re.compile(f"^{body}$"))


@dataclass
class Context:
    api: "OgwaApi"
    request: Request
    principal: Principal | None
    session: Session | None
    session_token: str | None

    @property
    def user(self) -> Principal:
        if self.principal is None:  # pragma: no cover - the pipeline guarantees a principal here
            raise unauthenticated()
        return self.principal


class OgwaApi:
    def __init__(self, *, store: Store, identity: IdentityAdapter, bindings: RoleBindings,
                 clock: Callable[[], datetime], mode: ExecutionMode, routes: Iterable[Route] | None = None,
                 sessions: SessionManager | None = None, mapping_gateway: MappingReviewGateway | None = None,
                 allowed_origins: Iterable[str] = (), logger: logging.Logger | None = None,
                 remediation_allowlist: RemediationAllowlist | None = None,
                 remediation_templates: Mapping[int, TemplateMetadata] | None = None,
                 quarantine_ous: QuarantineOus | None = None) -> None:
        if mode is not ExecutionMode.LOCAL_SYNTHETIC:
            raise ConfigError("The operator API serves only in LOCAL_SYNTHETIC mode in this build (D50).")
        if store.mode is not mode:
            raise ConfigError("the store was opened in a different execution mode")
        if bindings.environment is not store.marker.environment:
            raise ConfigError("the role bindings are for a different store environment")
        if bindings.issuer != identity.issuer:
            raise ConfigError("the role bindings name a different identity issuer than the identity adapter")
        from app.api.routes import ROUTES

        self.store = store
        self.identity = identity
        self.bindings = bindings
        self.clock = clock
        self.mode = mode
        self.sessions = sessions or SessionManager()
        self.read = ReadModel(store)
        self.directory = DirectoryView(store)  # the synthetic directory snapshot, if the store holds one
        # No quarantine OU configuration means no AD-stage step can pass (D136).
        self.lifecycle = LifecycleService(store, clock=clock, mode=mode, quarantine_ous=quarantine_ous)
        # No allowlist means no operation is available: every remediation dry run is BLOCKED.
        self.remediation = RemediationService(store, lifecycle=self.lifecycle, clock=clock, mode=mode,
                                              allowlist=remediation_allowlist,
                                              observed_templates=remediation_templates,
                                              quarantine_ous=quarantine_ous)
        self.mappings = MappingReviews(mapping_gateway)
        self.allowed_origins = frozenset(allowed_origins)
        self.log = logger or logging.getLogger("ogwa.api")
        self.routes = tuple(routes if routes is not None else ROUTES)

    # --- WSGI -------------------------------------------------------------------------

    def __call__(self, environ: dict[str, Any], start_response) -> list[bytes]:
        request_id = new_id(IdKind.REQUEST)
        started = time.perf_counter()
        method = str(environ.get("REQUEST_METHOD", "")).upper()
        route_label, principal = "-", None
        try:
            route, params = self._match(method, str(environ.get("PATH_INFO") or "/"))
            route_label = route.pattern
            response, principal = self._handle(route, params, environ, request_id)
        except ApiError as error:
            response = Response(error.status, error.body(request_id), list(error.headers))
            if error.status in (401, 403):
                self.log.warning("api.refused", extra={"ogwa": {
                    "request_id": request_id, "route": route_label, "method": method, "status": error.status,
                    "code": error.code, "principal": error.subject}})
        except StoreIntegrityError:
            self.log.error("api.integrity_failure", exc_info=True, extra={"ogwa": {"request_id": request_id,
                                                                                 "route": route_label}})
            response = Response(500, ApiError(500, "INTEGRITY_FAILURE", "Stored records failed verification. "
                                              "Quote the request id when reporting it.").body(request_id))
        except Exception:
            self.log.error("api.internal_error", exc_info=True, extra={"ogwa": {"request_id": request_id,
                                                                              "route": route_label}})
            response = Response(500, INTERNAL_ERROR.body(request_id))
        self._label_policy(response, request_id)
        status, headers, payload = response.encode(request_id)
        self.log.info("api.request", extra={"ogwa": {
            "request_id": request_id, "method": method, "route": route_label, "status": response.status,
            "principal": principal.subject if principal else None,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 1)}})
        start_response(status, headers)
        return [payload]

    def _match(self, method: str, path: str) -> tuple[Route, dict[str, str]]:
        if len(path) > MAX_PATH_LENGTH:
            raise ApiError(404, "NOT_FOUND", "No such resource.")
        allowed = []
        for route in self.routes:
            m = route.regex.match(path)
            if m is None:
                continue
            if route.method == method:
                return route, m.groupdict()
            allowed.append(route.method)
        if allowed:
            raise ApiError(405, "METHOD_NOT_ALLOWED", "Method not allowed here.",
                           headers=[("Allow", ", ".join(sorted(set(allowed))))])
        raise ApiError(404, "NOT_FOUND", "No such resource.")

    def _handle(self, route: Route, params: dict[str, str], environ: dict[str, Any],
                request_id: str) -> tuple[Response, Principal | None]:
        headers = read_headers(environ)
        if "authorization" in headers:
            raise ApiError(401, "UNSUPPORTED_AUTHENTICATION", "This API accepts only its session cookie. Bearer and "
                                                              "other Authorization schemes are not accepted.")
        cookies = read_cookies(headers)
        request = Request(route.method, str(environ.get("PATH_INFO")), {}, headers, cookies, None, request_id, params)
        if route.method == "POST":
            self._check_origin(request)

        token = cookies.get(SESSION_COOKIE)
        session = self.sessions.get(token) if route.access != "public" else None
        principal = None
        if route.access != "public":
            if session is None:
                raise unauthenticated()
            principal = Principal(session.claims, self.bindings.roles_for(session.claims))
            if route.method == "POST" and not SessionManager.csrf_matches(session, request.header(CSRF_HEADER)):
                error = forbidden("The CSRF token is missing or wrong. Read it from GET /api/v1/session.",
                                  code="CSRF_FAILED")
                error.subject = principal.subject
                raise error
            if route.access == "permission" and not principal.permissions & route.any_of:
                error = forbidden()
                error.subject = principal.subject
                raise error
        # Only now, for an authorized caller, are the query and body read and validated.
        request.query = read_query(environ)
        check_query(request.query, route.query)
        if route.method == "POST":
            request.body = read_json_body(environ, headers)
        context = Context(self, request, principal, session, token)
        try:
            response = route.handler(context)
        except ApiError as error:
            error.subject = principal.subject if principal else None
            if (route.governed_subject is not None and principal is not None
                    and error.status in GOVERNED_REFUSAL_STATUSES and error.code not in CHAINED_ELSEWHERE):
                self._chain_refusal(route, request, principal, error)
            raise
        # A cookie that carries its own idle clock is renewed on use, unless the handler set the cookie itself
        # (sign-out clears it).
        renewed = self.sessions.renew(session) if session is not None else None
        if renewed and not any(name.lower() == "set-cookie" for name, _ in response.headers):
            response.headers.append(session_cookie(SESSION_COOKIE, renewed, self.sessions.cookie_max_age))
        return response, principal

    def _chain_refusal(self, route: Route, request: Request, principal: Principal, error: ApiError) -> None:
        """Record a refused governed request in the audit chain (owner decision).

        Reached only after authentication, CSRF, the route's static permission, and body
        validation passed, so the request was a valid attempt. If recording fails, the
        refusal still stands (nothing changed) and the failure is logged. A read-only store
        (the public hosted demo) records nothing, so there the refusal is only logged."""
        if self.store.read_only:
            self.log.info("api.refusal_not_chained", extra={"ogwa": {
                "request_id": request.request_id, "route": route.pattern, "code": error.code,
                "reason": "the store is read-only"}})
            return
        details: dict[str, object] = {"route": f"{route.method} {route.pattern}", "code": error.code,
                                      "message": error.message}
        if error.problems:
            details["problems"] = " | ".join(error.problems)
        for name in _GOVERNED_DETAIL_FIELDS:
            value = (request.body or {}).get(name)
            if isinstance(value, (str, bool, int)) and not isinstance(value, float):
                details[f"request.{name}"] = str(value)[:120]
            elif isinstance(value, dict) and len(value) == 1:
                (key, inner), = value.items()
                if isinstance(key, str) and isinstance(inner, str):
                    details[f"request.{name}.{key[:40]}"] = inner[:120]
        try:
            event = self.store.record_governed_refusal(
                actor=principal.actor, subject_id=request.path_params[route.governed_subject][:100], details=details,
                correlation_id=request.request_id)
            error.audit_event_id = event.id
        except Exception:
            self.log.error("api.refusal_audit_failed", exc_info=True,
                           extra={"ogwa": {"request_id": request.request_id, "route": route.pattern}})

    def _label_policy(self, response: Response, request_id: str) -> None:
        """While the unrecorded demo policy is in force, say so on every response."""
        try:
            in_force = policy_in_force(self.store)
        except ApiError:
            return  # no policy at all: nothing is judged, and the policy views say why
        except Exception:
            self.log.error("api.policy_label_failed", exc_info=True, extra={"ogwa": {"request_id": request_id}})
            response.body = {**response.body, "policyNotice": "POLICY STATUS UNAVAILABLE"}
            return
        if not in_force.recorded:
            response.body = {**response.body, "policyNotice": in_force.label}
            response.headers.append(("X-OGWA-Policy-Status", "DEMO-UNRECORDED"))

    def _check_origin(self, request: Request) -> None:
        """Refuse cross-site POSTs. Non-browser clients send neither header and rely on the CSRF token."""
        origin = request.header("origin")
        if origin is not None and origin not in self.allowed_origins:
            raise forbidden("Requests from this origin are not accepted.", code="ORIGIN_REFUSED")
        fetch_site = request.header("sec-fetch-site")
        if origin is None and fetch_site is not None and fetch_site not in _SAME_SITE_FETCH:
            raise forbidden("Cross-site requests are not accepted.", code="ORIGIN_REFUSED")
