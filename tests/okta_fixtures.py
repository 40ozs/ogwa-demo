"""Synthetic Okta fixtures. Every id, name, and token here is invented.

Hosts use the reserved ``.example`` TLD (RFC 2606). Okta-style ids are built from a
``SYNTH`` marker so they can never be mistaken for real tenant ids.
"""

import base64
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone

from app.core.http_client import HttpPolicy, HttpResponse
from app.core.modes import ExecutionMode
from app.core.secret import Secret
from app.integrations.okta.auth import PERMITTED_SCOPES, AccessTokenGrant, StaticGrantProvider
from app.integrations.okta.client import OktaReadOnlyClient
from app.integrations.okta.pacing import PacingPolicy
from tests.fakes import SYNTHETIC_OKTA_URL, FakeTransport, RecordingSleep

NOW = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
SYNTHETIC_ACCESS_TOKEN = "synthetic-okta-access-token-0001"

APP_A = "0oaSYNTHAPP0000000A1"
APP_B = "0oaSYNTHAPP0000000B2"
APP_C = "0oaSYNTHAPP0000000C3"
GROUP_1 = "00gSYNTHGRP000000011"
GROUP_2 = "00gSYNTHGRP000000022"
GROUP_3 = "00gSYNTHGRP000000033"
AD_INTEGRATION = "0oaSYNTHADINTEGRATN9"
USER_1 = "00uSYNTHUSR000000001"
USER_2 = "00uSYNTHUSR000000002"
USER_3 = "00uSYNTHUSR000000003"

SYNTHETIC_GUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
SYNTHETIC_SID = "S-1-5-21-1111111111-2222222222-3333333333-41001"


class GetOnlyTransport(FakeTransport):
    """FakeTransport that fails the test if anything other than GET is sent."""

    def send(self, method, url, headers, body, **kwargs):
        if method != "GET" or body is not None:
            raise AssertionError(f"Okta read-only client sent {method} with body={body is not None}")
        return super().send(method, url, headers, body, **kwargs)


def grant(scopes=PERMITTED_SCOPES, *, expires_at=NOW + timedelta(hours=1)) -> AccessTokenGrant:
    return AccessTokenGrant(access_token=Secret(SYNTHETIC_ACCESS_TOKEN), scopes=frozenset(scopes), expires_at=expires_at)


def respond(body=None, *, status=200, next_url=None, headers=None, raw: bytes | None = None) -> HttpResponse:
    hdrs = dict(headers or {})
    if next_url:
        hdrs["Link"] = f'<{SYNTHETIC_OKTA_URL}/api/v1/self>; rel="self", <{next_url}>; rel="next"'
    data = raw if raw is not None else (b"" if body is None else json.dumps(body).encode())
    return HttpResponse(status, hdrs, data)


def page_url(path: str, cursor: str) -> str:
    return f"{SYNTHETIC_OKTA_URL}{path}?limit=200&after={cursor}"


_QUIET = logging.getLogger("ogwa.test.okta")
_QUIET.addHandler(logging.NullHandler())
_QUIET.propagate = False


def make_client(*responses, pacing=None, policy=None, credentials=None, rng=lambda: 0.5, now=NOW, logger=None):
    transport = GetOnlyTransport(*responses)
    sleep = RecordingSleep()
    client = OktaReadOnlyClient(
        org_url=SYNTHETIC_OKTA_URL,
        mode=ExecutionMode.READ_ONLY_PRODUCTION,
        http_policy=policy or HttpPolicy(),
        credentials=credentials or StaticGrantProvider(grant()),
        pacing=pacing or PacingPolicy(min_interval_seconds=0),
        transport=transport,
        logger=logger or _QUIET,
        sleep=sleep,
        rng=rng,
        now=lambda: now,
        monotonic=lambda: 0.0,
    )
    return client, transport, sleep


def app_json(app_id, *, status="ACTIVE", label="SYNTH App", sign_on_mode="SAML_2_0", **extra):
    body = {"id": app_id, "status": status, "label": label, "name": "synthetic_app", "signOnMode": sign_on_mode,
            "created": "2025-01-02T03:04:05.000Z", "lastUpdated": "2026-02-03T04:05:06.000Z"}
    body.update(extra)
    return {k: v for k, v in body.items() if v is not None}


def guid_external_id(guid: str = SYNTHETIC_GUID) -> str:
    return base64.b64encode(uuid.UUID(guid).bytes_le).decode()


def group_json(group_id, *, group_type="OKTA_GROUP", name="SYNTH Group", ad=False):
    body = {"id": group_id, "type": group_type, "profile": {"name": name},
            "lastUpdated": "2026-03-01T00:00:00.000Z", "lastMembershipUpdated": "2026-04-01T00:00:00.000Z"}
    if ad:
        body["profile"].update({
            "externalId": guid_external_id(), "objectSid": SYNTHETIC_SID,
            "windowsDomainQualifiedName": "SYNTH\\SYNTH-GROUP", "dn": "CN=SYNTH-GROUP,DC=corp,DC=synthetic,DC=example",
            "samAccountName": "SYNTH-GROUP",
        })
        body["_links"] = {"source": {"href": f"{SYNTHETIC_OKTA_URL}/api/v1/apps/{AD_INTEGRATION}"}}
    return body


def assignment_json(group_id, *, priority=0, embed=None):
    body = {"id": group_id, "priority": priority, "lastUpdated": "2026-05-01T00:00:00.000Z"}
    if embed is not None:
        body["_embedded"] = {"group": embed}
    return body


def member_json(user_id, *, status="ACTIVE"):
    return {"id": user_id, "status": status,
            "profile": {"login": f"{user_id.lower()}@synthetic.example", "email": f"{user_id.lower()}@synthetic.example",
                        "firstName": "Synth", "lastName": "User"}}


def event_json(app_id, actor_id, published: datetime, *, extra_targets=()):
    return {
        "uuid": str(uuid.uuid4()),
        "eventType": "user.authentication.sso",
        "published": published.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "actor": {"id": actor_id, "type": "User", "alternateId": f"{(actor_id or 'x').lower()}@synthetic.example"},
        "outcome": {"result": "SUCCESS"},
        "target": [{"id": app_id, "type": "AppInstance", "displayName": "SYNTH App"}, *extra_targets],
    }
