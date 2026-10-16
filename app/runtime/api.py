"""The demo runtime's API and UI: the real OGWA application over the demo store.

Nothing here is a demo-only view or service. The demo serves the application's own
``OgwaApi``, read model, lifecycle and remediation services, correlation engine, and
operator UI, built by ``app.api.local.build_local_api`` with the synthetic providers that
``app.runtime.providers.select_providers`` chose. This module adds only:

- **the mutation policy for demo** (``DEMO_MUTATION_POLICY``): every POST route is
  classified before the API is built, and an unclassified one stops the build, so a route
  added later cannot reach the demo unreviewed;
- **demo labels**: ``GET /health`` and ``GET /dashboard`` carry the runtime and dataset
  metadata, every response carries ``X-OGWA-Runtime-Mode: demo``, and successful simulated
  operations say plainly that nothing was changed;
- **the blocked route**: ``POST /execution-jobs/{jobId}/execute`` answers
  ``DEMO_MODE_BLOCKED`` (403) before the lifecycle service is reached. The refusal is chained
  in the demo store's audit log like every refused governed request.
- **read-only demos**: over a read-only demo store (the public hosted demo,
  docs/deployment/cloudflare-demo.md) every POST that would record something answers
  ``DEMO_READ_ONLY`` (403), to any visitor. Only the ``NON_PERSISTING`` routes stay open:
  sign-out, mapping inspection, AD search, and the synthetic drill, which record nothing.
- **the public demo is anonymous**: a read-only demo has no sign-in. ``GET /session``
  gives a visitor without a session a new one for the synthetic,
  anonymous ``VISITOR_SUBJECT`` (the VIEWER role, from the role bindings), and ``POST /session``
  answers ``PUBLIC_DEMO_NO_SIGN_IN``, so no visitor can choose a principal. The visitor may
  run the synthetic drill on the walkthrough's ``publicDrill`` candidate only (NM-C11): for
  that one request, on that one candidate, it holds the executor's role; never in its session.

Mutation classes (docs/demo-mode.md):

- ``LOCAL``: changes only the demo store (review decisions, approvals, mapping reviews);
- ``SIMULATED``: a plan or simulation recorded in the demo store; no external system is
  contacted, and the response says so;
- ``BLOCKED``: refused in demo.
"""

from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any

from app.api.app import API_PREFIX, Context, Route
from app.api.authz import Permission, Principal, Role
from app.api.errors import ApiError
from app.api.http import Response, session_cookie
from app.api.identity import PrincipalClaims
from app.api.sessions import CSRF_HEADER, SESSION_COOKIE
from app.api.local import build_local_api
from app.api.validation import Body, path_id
from app.core.config import Settings
from app.core.errors import ConfigError
from app.domain.ids import IdKind
from app.runtime.datasets import DatasetMetadata, DemoDataset, resolve_dataset
from app.runtime.demo_store import DemoStoreReport, open_demo_store
from app.runtime.providers import IntegrationProviders, select_providers
from app.store.store import Store

RUNTIME_HEADER = "X-OGWA-Runtime-Mode"
SIMULATION_NOTICE = "Simulation only — no Okta tenant was modified."
LOCAL_NOTICE = "Recorded in the demo store only — no Okta tenant, directory, or AAP controller is connected."
NOTHING_RECORDED_NOTICE = ("Computed from the demo store; nothing was recorded, and no Okta tenant, directory, or AAP "
                           "controller is connected.")
BLOCKED_MESSAGE = ("Execution is blocked in the demo environment. No Okta tenant, Active Directory, or AAP controller "
                   "is connected, and nothing was run or changed.")

LOCAL, SIMULATED, BLOCKED, SESSION = "LOCAL", "SIMULATED", "BLOCKED", "SESSION"
# Every POST route of the API, by pattern below /api/v1. The build fails on any other.
DEMO_MUTATION_POLICY: dict[str, str] = {
    "/session": SESSION,
    "/session/logout": SESSION,
    "/candidates/{candidateId}/transitions": LOCAL,
    "/candidates/{candidateId}/approvals": LOCAL,
    "/mappings/{groupId}/inspection": LOCAL,
    "/mappings/{groupId}/searches": LOCAL,
    "/mappings/{groupId}/selections": LOCAL,
    "/mappings/{groupId}/approvals": LOCAL,
    "/mappings/{groupId}/rejections": LOCAL,
    "/candidates/{candidateId}/execution-jobs": SIMULATED,
    "/candidates/{candidateId}/remediation-dry-runs": SIMULATED,
    # Changes only an in-memory provider fixture, and records nothing.
    "/candidates/{candidateId}/remediation-drills": SIMULATED,
    "/execution-jobs/{jobId}/execute": BLOCKED,
}
# POST routes that record nothing in the demo store: sessions and search results live in
# process memory, an inspection is computed, and a remediation drill's provider fixture is
# discarded when it returns. Only these stay open in a read-only demo.
NON_PERSISTING: frozenset[str] = frozenset({
    "/session", "/session/logout", "/mappings/{groupId}/inspection", "/mappings/{groupId}/searches",
    "/candidates/{candidateId}/remediation-drills",
})
READ_ONLY_MESSAGE = ("This public demo is read-only: visitors share one demo store, and it is never changed, so "
                     "nothing was recorded. Run OGWA locally to try lifecycle decisions and approvals.")

# The public demo's one principal: synthetic, anonymous, and granted roles only by the role bindings.
VISITOR_SUBJECT = "public.visitor"
VISITOR_NAME = "Public demo visitor"
VISITOR_METHOD = "anonymous-public-demo"
NO_SIGN_IN_MESSAGE = ("This public demo has no sign-in: every visitor is the same anonymous, read-only synthetic "
                      "viewer. Run OGWA locally to sign in as its synthetic principals.")
DRILL_SCOPE_MESSAGE = ("In this public demo, the synthetic drill runs only on the walkthrough's controlled-remediation "
                       "candidate (NM-C11). Nothing was run.")


@dataclass(frozen=True)
class RuntimeProfile:
    """What the demo says about itself. Non-sensitive: no paths, hosts, or credentials."""

    runtime_mode: str
    data_source: str
    dataset: DatasetMetadata
    public: bool = False  # the anonymous, read-only public demo

    def to_json(self) -> dict[str, Any]:
        return {"runtimeMode": self.runtime_mode, "dataSource": self.data_source,
                "organization": self.dataset.company_name, "dataset": self.dataset.to_json(),
                "liveIntegrations": False, "publicDemo": self.public}


def demo_blocked() -> ApiError:
    return ApiError(403, "DEMO_MODE_BLOCKED", BLOCKED_MESSAGE)


def demo_read_only() -> ApiError:
    return ApiError(403, "DEMO_READ_ONLY", READ_ONLY_MESSAGE)


def _with(body: dict[str, Any], key: str, value: Any) -> dict[str, Any]:
    return {**body, key: value}


def demo_routes(routes: Iterable[Route], profile: RuntimeProfile, *, read_only: bool = False) -> tuple[Route, ...]:
    """``routes`` with the demo's labels and mutation policy applied. Access rules are unchanged.

    ``read_only``: every POST outside ``NON_PERSISTING`` is refused, except that a BLOCKED
    route keeps its own refusal."""
    if not NON_PERSISTING <= DEMO_MUTATION_POLICY.keys():
        raise ConfigError("NON_PERSISTING names a route the demo mutation policy does not classify")
    out = []
    for route in routes:
        path = route.pattern[len(API_PREFIX):]
        handler, kind = route.handler, None
        if route.method == "POST":
            kind = DEMO_MUTATION_POLICY.get(path)
            if kind is None:
                raise ConfigError(f"POST {route.pattern} has no demo mutation classification; add it to "
                                  "app.runtime.api.DEMO_MUTATION_POLICY before serving the demo")
            if kind == BLOCKED:
                handler = _blocked(route)
            elif read_only and path not in NON_PERSISTING:
                handler = _read_only
            elif kind in (LOCAL, SIMULATED):
                handler = _labelled(handler, kind, NOTHING_RECORDED_NOTICE if read_only else None)
        elif path == "/health":
            handler = _health(profile)
        elif path == "/dashboard":
            handler = _dashboard(handler, profile)
        route = replace(route, handler=handler)
        if read_only:
            route = _public(route, path, refuses=route.method == "POST" and (kind == BLOCKED or handler is _read_only))
        out.append(route)
    missing = {f"POST {API_PREFIX}{p}" for p in DEMO_MUTATION_POLICY} - {f"{r.method} {r.pattern}" for r in out}
    if missing:
        raise ConfigError(f"the demo mutation policy names routes the API does not have: {', '.join(sorted(missing))}")
    return tuple(out)


def _health(profile: RuntimeProfile) -> Callable[[Context], Response]:
    def health(ctx: Context) -> Response:
        return Response(200, {"status": "ok", **profile.to_json()}, [])
    return health


def _dashboard(inner: Callable[[Context], Response], profile: RuntimeProfile) -> Callable[[Context], Response]:
    def dashboard(ctx: Context) -> Response:
        response = inner(ctx)
        response.body = _with(response.body, "runtime", profile.to_json())
        return response
    return dashboard


def _labelled(inner: Callable[[Context], Response], kind: str, notice: str | None = None) -> Callable[[Context], Response]:
    notice = notice or (SIMULATION_NOTICE if kind == SIMULATED else LOCAL_NOTICE)

    def labelled(ctx: Context) -> Response:
        response = inner(ctx)
        if 200 <= response.status < 300:
            response.body = _with(response.body, "demo", {"classification": kind, "notice": notice,
                                                          "externalSystemsContacted": False})
        return response
    return labelled


def _blocked(route: Route) -> Callable[[Context], Response]:
    def blocked(ctx: Context) -> Response:
        if route.pattern.endswith("/execute"):
            path_id(ctx.request.path_params["jobId"], IdKind.EXECUTION_JOB, "execution job")
        Body(ctx.request.body, allowed=())
        raise demo_blocked()
    return blocked


def _read_only(ctx: Context) -> Response:
    raise demo_read_only()


# --- the public demo: anonymous and read-only -----------------------------------------------


def _public(route: Route, path: str, *, refuses: bool) -> Route:
    """A read-only demo's route as the anonymous public demo serves it (module docstring).
    ``refuses``: its handler refuses every request, so any visitor gets its explanation, not a bare 403."""
    if route.method == "GET" and path == "/session":
        return replace(route, access="public", handler=_visitor_session)
    if route.method == "POST" and path == "/session":
        return replace(route, handler=_no_sign_in)
    if route.method == "POST" and path == "/candidates/{candidateId}/remediation-drills":
        return replace(route, any_of=frozenset({Permission.READ_INVENTORY}), handler=_public_drill(route.handler))
    if refuses:
        return replace(route, access="session", any_of=frozenset())
    return route


def visitor_claims(api, now: datetime) -> PrincipalClaims:
    """The anonymous visitor: the role bindings' VIEWER groups, and nothing else."""
    groups = frozenset(b.idp_group_id for b in api.bindings.bindings if b.role is Role.VIEWER)
    claims = PrincipalClaims(api.bindings.issuer, VISITOR_SUBJECT, VISITOR_NAME, groups, now, VISITOR_METHOD)
    if api.bindings.roles_for(claims) != {Role.VIEWER}:
        raise ConfigError("the role bindings must bind a group to VIEWER alone for the public demo's visitor")
    return claims


def public_drill_candidates(api) -> frozenset[str]:
    """The candidates a public visitor may drill: the walkthrough parts marked ``publicDrill`` (NM-C11)."""
    from app.demo.datasets import dataset_of

    guide = dataset_of(api.store).walkthrough(public=True)
    if guide is None:
        return frozenset()
    ids = {s.get("candidateKey"): s.get("candidateId") for s in api.directory.scenarios()}
    return frozenset(ids[p["candidateKey"]] for p in guide["parts"]
                     if p.get("publicDrill") and ids.get(p["candidateKey"]))


def _visitor_session(ctx: Context) -> Response:
    """``GET /session``: the visitor's session, or a new anonymous one. Never a sign-in."""
    api = ctx.api
    session = api.sessions.get(ctx.request.cookies.get(SESSION_COOKIE))
    headers = []
    if session is None:
        token, session = api.sessions.create(visitor_claims(api, api.clock()))
        headers.append(session_cookie(SESSION_COOKIE, token, api.sessions.cookie_max_age))
    principal = Principal(session.claims, api.bindings.roles_for(session.claims))
    return Response(200, {"principal": {**principal.to_dict(),
                                        "publicDrillCandidates": sorted(public_drill_candidates(api))},
                          "csrfToken": session.csrf_token, "csrfHeader": CSRF_HEADER}, headers)


def _no_sign_in(ctx: Context) -> Response:
    raise ApiError(403, "PUBLIC_DEMO_NO_SIGN_IN", NO_SIGN_IN_MESSAGE)


def _public_drill(inner: Callable[[Context], Response]) -> Callable[[Context], Response]:
    def drill(ctx: Context) -> Response:
        if ctx.request.path_params["candidateId"] not in public_drill_candidates(ctx.api):
            raise ApiError(403, "PUBLIC_DRILL_SCOPE", DRILL_SCOPE_MESSAGE)
        # The executor's role for this one request on this one candidate; the session keeps VIEWER.
        return inner(replace(ctx, principal=Principal(ctx.user.claims, frozenset({Role.EXECUTOR}))))
    return drill


class RuntimeHeader:
    """WSGI middleware: every response says which runtime answered it."""

    def __init__(self, app: Callable, runtime_mode: str) -> None:
        self.app = app
        self.runtime_mode = runtime_mode

    def __call__(self, environ: dict[str, Any], start_response) -> Iterable[bytes]:
        def start(status, headers, exc_info=None):
            headers = [*headers, (RUNTIME_HEADER, self.runtime_mode)]
            return start_response(status, headers) if exc_info is None else start_response(status, headers, exc_info)
        return self.app(environ, start)


@dataclass
class DemoApplication:
    web_app: Callable
    api: Any
    store: Store
    dataset: DemoDataset
    providers: IntegrationProviders
    report: DemoStoreReport
    profile: RuntimeProfile

    def close(self) -> None:
        self.store.close()


def build_demo_application(settings: Settings, *, clock: Callable[[], datetime], port: int | None = None,
                           logger=None, dataset: DemoDataset | None = None,
                           store_clock: Callable[[], datetime] | None = None,
                           opened: tuple[Store, DemoStoreReport] | None = None, assets=None) -> DemoApplication:
    """Open and validate the demo store, select the demo providers, and build the real UI and API.

    ``opened``: a demo store already opened and validated for ``dataset`` (``open_demo_image``),
    used instead of opening the file. A read-only store gets the read-only route policy.
    ``assets``: the UI files for ``OgwaWebApp``, when a host serves them some other way."""
    from app.ui.server import OgwaWebApp

    dataset = dataset or resolve_dataset(settings.demo_dataset)
    if opened is None:
        store, report = open_demo_store(settings, dataset, clock=store_clock or clock)
    else:
        store, report = opened
        if report.dataset != dataset.key:
            raise ConfigError(f"the opened demo store holds {report.dataset!r}, not the configured {dataset.key!r}")
    try:
        providers = select_providers(store=store, dataset=dataset, clock=clock)
        profile = RuntimeProfile(settings.runtime_mode.value, providers.data_source, dataset.metadata,
                                 public=store.read_only)
        from app.api.routes import ROUTES

        api = build_local_api(store, clock=clock, port=port, mapping_gateway=providers.ad_directory, logger=logger,
                              remediation_allowlist=providers.remediation_allowlist,
                              routes=demo_routes(ROUTES, profile, read_only=store.read_only))
        web_app = RuntimeHeader(OgwaWebApp(api, assets), settings.runtime_mode.value)
    except BaseException:
        store.close()
        raise
    return DemoApplication(web_app, api, store, dataset, providers, report, profile)
