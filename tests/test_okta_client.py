"""Read-only Okta client: auth, pagination, rate limits, failures, normalization, safety.

Synthetic data and fake transports only, plus one throwaway loopback server for the
duplicate-header transport check. Nothing here contacts Okta.
"""

import ast
import http.server
import json
import logging
import threading
import unittest
from datetime import timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from app.core.config import load_settings
from app.core.errors import NetworkPolicyError
from app.core.http_client import HttpPolicy, ReadOnlyHttpClient, StdlibTransport, TransportError, combine_headers
from app.core.modes import ExecutionMode
from app.domain.collection import CollectorErrorCode
from app.domain.evidence import ResultStatus
from app.integrations.okta.auth import (
    SCOPE_APPS_READ,
    OktaCredentialError,
    StaticGrantProvider,
)
from app.integrations.okta.client import OktaReadOnlyClient
from app.integrations.okta.models import AppStatus, GroupType, StopReason
from app.integrations.okta.normalize import decode_object_guid
from app.integrations.okta.pacing import OktaRequestExecutor, PacingPolicy
from tests.fakes import SYNTHETIC_OKTA_URL, read_only_env, captured_logs
from tests.okta_fixtures import (
    AD_INTEGRATION,
    APP_A,
    APP_B,
    APP_C,
    GROUP_1,
    GROUP_2,
    GROUP_3,
    NOW,
    SYNTHETIC_ACCESS_TOKEN,
    SYNTHETIC_GUID,
    SYNTHETIC_SID,
    USER_1,
    USER_2,
    USER_3,
    GetOnlyTransport,
    app_json,
    assignment_json,
    grant,
    group_json,
    make_client,
    member_json,
    page_url,
    respond,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
OKTA_PACKAGE = REPO_ROOT / "app" / "integrations"


def _query(url):
    return {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}


class AuthenticationTests(unittest.TestCase):
    def test_sends_bearer_access_token_never_ssws(self):
        client, transport, _ = make_client(respond([app_json(APP_A)]))
        client.list_applications()
        self.assertEqual(transport.calls[0]["headers"]["Authorization"], f"Bearer {SYNTHETIC_ACCESS_TOKEN}")

    def test_grant_with_write_scope_is_refused(self):
        for scope in ("okta.apps.manage", "okta.groups.manage", "okta.users.read", "okta.logs.manage"):
            with self.subTest(scope=scope), self.assertRaises(OktaCredentialError):
                grant({SCOPE_APPS_READ, scope})

    def test_grant_without_scopes_is_refused(self):
        with self.assertRaises(OktaCredentialError):
            grant(set())

    def test_missing_scope_fails_before_any_request(self):
        client, transport, _ = make_client(credentials=StaticGrantProvider(grant({SCOPE_APPS_READ})))
        lookup = client.get_group(GROUP_1)
        self.assertEqual(lookup.status, ResultStatus.FAILED)
        self.assertEqual(lookup.error_code, CollectorErrorCode.AUTHENTICATION_FAILED)
        self.assertEqual(transport.calls, [])
        self.assertIsNotNone(client.halted)

    def test_expired_token_fails_before_any_request(self):
        expired = StaticGrantProvider(grant(expires_at=NOW + timedelta(seconds=30)))
        client, transport, _ = make_client(credentials=expired)
        listing = client.list_applications()
        self.assertEqual(listing.status, ResultStatus.FAILED)
        self.assertEqual(listing.error_code, CollectorErrorCode.AUTHENTICATION_FAILED)
        self.assertEqual(transport.calls, [])

    def test_401_halts_the_session_without_retry(self):
        client, transport, sleep = make_client(respond({"errorCode": "E0000011"}, status=401))
        listing = client.list_applications()
        self.assertEqual(listing.error_code, CollectorErrorCode.AUTHENTICATION_FAILED)
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(sleep.delays, [])
        again = client.get_application(APP_A)  # halted: nothing more is sent
        self.assertEqual(again.status, ResultStatus.FAILED)
        self.assertEqual(len(transport.calls), 1)

    def test_403_is_an_authorization_failure(self):
        client, _, _ = make_client(respond(status=403))
        self.assertEqual(client.list_applications().error_code, CollectorErrorCode.AUTHENTICATION_FAILED)

    def test_from_settings_ignores_the_ssws_placeholder(self):
        settings = load_settings(read_only_env())
        self.assertIsNotNone(settings.okta_api_token)  # present in the environment...
        transport = GetOnlyTransport(respond([]))
        client = OktaReadOnlyClient.from_settings(settings, credentials=StaticGrantProvider(grant()),
                                                  transport=transport, now=lambda: NOW)
        client.list_applications()
        auth = transport.calls[0]["headers"]["Authorization"]
        self.assertTrue(auth.startswith("Bearer "))  # ...but never sent
        self.assertNotIn(settings.okta_api_token.reveal(), auth)

    def test_credentials_are_required(self):
        with self.assertRaises(TypeError):
            OktaReadOnlyClient(org_url=SYNTHETIC_OKTA_URL, mode=ExecutionMode.READ_ONLY_PRODUCTION,
                               http_policy=HttpPolicy(), credentials=None)

    def test_grant_repr_never_shows_token(self):
        self.assertNotIn(SYNTHETIC_ACCESS_TOKEN, repr(grant()))
        self.assertNotIn(SYNTHETIC_ACCESS_TOKEN, repr(StaticGrantProvider(grant())))


class PaginationTests(unittest.TestCase):
    def test_follows_next_links_until_the_last_page(self):
        client, transport, _ = make_client(
            respond([app_json(APP_A)], next_url=page_url("/api/v1/apps", "c1")),
            respond([app_json(APP_B)], next_url=page_url("/api/v1/apps", "c2")),
            respond([app_json(APP_C, status="INACTIVE")]),
        )
        listing = client.list_applications()
        self.assertEqual(listing.status, ResultStatus.COMPLETE)
        self.assertEqual([a.okta_app_id for a in listing.items], [APP_A, APP_B, APP_C])
        self.assertEqual(listing.pages, 3)
        self.assertEqual(_query(transport.calls[0]["url"]), {"limit": "200"})
        self.assertEqual(_query(transport.calls[2]["url"])["after"], "c2")
        self.assertIsNone(listing.error_code)

    def test_status_filter_is_sent(self):
        client, transport, _ = make_client(respond([]))
        listing = client.list_applications(status=AppStatus.INACTIVE)
        self.assertEqual(_query(transport.calls[0]["url"])["filter"], 'status eq "INACTIVE"')
        self.assertEqual(listing.status, ResultStatus.COMPLETE)  # an empty listing is complete
        self.assertEqual(listing.items, ())

    def test_next_link_to_another_host_is_not_followed(self):
        client, transport, _ = make_client(
            respond([app_json(APP_A)], next_url="https://elsewhere.synthetic.example/api/v1/apps?after=x"))
        listing = client.list_applications()
        self.assertEqual(listing.status, ResultStatus.PARTIAL)
        self.assertEqual(listing.stop_reason, StopReason.UNSAFE_NEXT_LINK)
        self.assertEqual(len(transport.calls), 1)

    def test_next_link_to_another_endpoint_is_not_followed(self):
        client, transport, _ = make_client(
            respond([app_json(APP_A)], next_url=f"{SYNTHETIC_OKTA_URL}/api/v1/users?after=x"))
        self.assertEqual(client.list_applications().stop_reason, StopReason.UNSAFE_NEXT_LINK)
        self.assertEqual(len(transport.calls), 1)

    def test_pagination_loop_is_detected(self):
        loop = page_url("/api/v1/apps", "same")
        client, transport, _ = make_client(
            respond([app_json(APP_A)], next_url=loop), respond([app_json(APP_B)], next_url=loop))
        listing = client.list_applications()
        self.assertEqual(listing.status, ResultStatus.PARTIAL)
        self.assertEqual(listing.stop_reason, StopReason.UNSAFE_NEXT_LINK)
        self.assertEqual(len(transport.calls), 2)

    def test_combined_link_header_with_next_first(self):
        client, _, _ = make_client(
            respond([app_json(APP_A)], headers={"Link": f'<{page_url("/api/v1/apps", "n")}>; rel="next", '
                                                        f'<{SYNTHETIC_OKTA_URL}/api/v1/apps>; rel="self"'}),
            respond([app_json(APP_B)]),
        )
        self.assertEqual(client.list_applications().pages, 2)


class PaginationHardeningTests(unittest.TestCase):
    """Owner-requested verification (2026-10-05): same-origin pagination, cyclic-link
    protection, and request-budget termination."""

    UNSAFE_NEXT_LINKS = {
        "plain http downgrade": "http://okta.synthetic.example/api/v1/apps?after=x",
        "different port": "https://okta.synthetic.example:8443/api/v1/apps?after=x",
        "explicit default port (fails closed)": "https://okta.synthetic.example:443/api/v1/apps?after=x",
        "embedded userinfo": "https://user:pw@okta.synthetic.example/api/v1/apps?after=x",
        "userinfo host trick": "https://okta.synthetic.example@elsewhere.synthetic.example/api/v1/apps?after=x",
        "backslash host trick": "https://okta.synthetic.example\\@elsewhere.synthetic.example/api/v1/apps?after=x",
        "look-alike suffix": "https://okta.synthetic.example.elsewhere.example/api/v1/apps?after=x",
        "sub-domain": "https://evil.okta.synthetic.example/api/v1/apps?after=x",
        "relative link": "/api/v1/apps?after=x",
        "protocol-relative": "//elsewhere.synthetic.example/api/v1/apps?after=x",
        "other endpoint": f"{SYNTHETIC_OKTA_URL}/api/v1/users?after=x",
        "deeper path": f"{SYNTHETIC_OKTA_URL}/api/v1/apps/{APP_A}/users?after=x",
        "dot-segment path": f"{SYNTHETIC_OKTA_URL}/api/v1/apps/../users?after=x",
        "trailing slash": f"{SYNTHETIC_OKTA_URL}/api/v1/apps/?after=x",
        "non-http scheme": "file:///api/v1/apps?after=x",
    }

    def test_every_off_origin_or_off_endpoint_next_link_is_refused(self):
        for label, link in self.UNSAFE_NEXT_LINKS.items():
            with self.subTest(label):
                client, transport, _ = make_client(respond([app_json(APP_A)], next_url=link), respond([app_json(APP_B)]))
                listing = client.list_applications()
                self.assertEqual(listing.status, ResultStatus.PARTIAL)
                self.assertEqual(listing.stop_reason, StopReason.UNSAFE_NEXT_LINK)
                self.assertEqual(listing.error_code, CollectorErrorCode.PAGING_INTERRUPTED)
                self.assertEqual([a.okta_app_id for a in listing.items], [APP_A])
                self.assertEqual(len(transport.calls), 1)

    def test_same_origin_with_different_host_case_is_followed(self):
        client, transport, _ = make_client(
            respond([app_json(APP_A)], next_url="https://OKTA.Synthetic.Example/api/v1/apps?after=c1"),
            respond([app_json(APP_B)]))
        self.assertTrue(client.list_applications().complete)
        self.assertEqual(len(transport.calls), 2)

    def test_two_step_cycle_is_stopped_before_a_third_request(self):
        a, b = page_url("/api/v1/apps", "a"), page_url("/api/v1/apps", "b")
        client, transport, _ = make_client(respond([app_json(APP_A)], next_url=a), respond([app_json(APP_B)], next_url=b),
                                           respond([app_json(APP_C)], next_url=a))
        listing = client.list_applications()
        self.assertEqual(listing.stop_reason, StopReason.UNSAFE_NEXT_LINK)
        self.assertEqual(len(transport.calls), 3)
        self.assertEqual(len(listing.items), 3)

    def test_next_link_back_to_the_first_page_is_a_cycle(self):
        first = f"{SYNTHETIC_OKTA_URL}/api/v1/apps?limit=200"
        client, transport, _ = make_client(respond([app_json(APP_A)], next_url=first))
        self.assertEqual(client.list_applications().stop_reason, StopReason.UNSAFE_NEXT_LINK)
        self.assertEqual(len(transport.calls), 1)

    def test_cosmetically_different_urls_do_not_hide_a_cycle(self):
        a = f"{SYNTHETIC_OKTA_URL}/api/v1/apps?limit=200&after=a"
        a_reordered = "https://OKTA.synthetic.example/api/v1/apps?after=a&limit=200"
        client, transport, _ = make_client(respond([app_json(APP_A)], next_url=a),
                                           respond([app_json(APP_B)], next_url=a_reordered))
        self.assertEqual(client.list_applications().stop_reason, StopReason.UNSAFE_NEXT_LINK)
        self.assertEqual(len(transport.calls), 2)

    def test_endless_distinct_cursors_terminate_at_the_budget(self):
        endless = [respond([app_json(APP_A)], next_url=page_url("/api/v1/apps", f"c{i}")) for i in range(20)]
        client, transport, _ = make_client(*endless, pacing=PacingPolicy(max_requests=5, min_interval_seconds=0))
        listing = client.list_applications()
        self.assertEqual(len(transport.calls), 5)
        self.assertEqual(listing.status, ResultStatus.PARTIAL)
        self.assertEqual(listing.stop_reason, StopReason.BUDGET_EXHAUSTED)
        self.assertEqual(listing.duplicates_dropped, 4)  # the same app on every page
        self.assertIsNotNone(client.halted)

    def test_exhausted_budget_sends_nothing_more_in_the_session(self):
        client, transport, _ = make_client(
            respond([app_json(APP_A)], next_url=page_url("/api/v1/apps", "c1")), respond([]),
            pacing=PacingPolicy(max_requests=1, min_interval_seconds=0))
        client.list_applications()
        for call in (lambda: client.get_application(APP_A), lambda: client.get_group(GROUP_1),
                     lambda: client.list_group_members(GROUP_1),
                     lambda: client.list_application_group_assignments(APP_A)):
            result = call()
            self.assertEqual(result.status, ResultStatus.FAILED)
            self.assertEqual(result.error_code, CollectorErrorCode.PAGING_INTERRUPTED)
        self.assertEqual(len(transport.calls), 1)

    def test_budget_equal_to_the_pages_needed_completes_without_halting(self):
        client, transport, _ = make_client(
            respond([app_json(APP_A)], next_url=page_url("/api/v1/apps", "c1")), respond([app_json(APP_B)]),
            pacing=PacingPolicy(max_requests=2, min_interval_seconds=0))
        self.assertTrue(client.list_applications().complete)
        self.assertIsNone(client.halted)
        self.assertEqual(client.budget_remaining, 0)
        self.assertEqual(client.get_application(APP_A).status, ResultStatus.FAILED)  # the next call is refused
        self.assertEqual(len(transport.calls), 2)

    def test_budget_is_never_exceeded_by_retries_or_throttling(self):
        reset = str(int(NOW.timestamp()) + 5)
        low = {"X-Rate-Limit-Limit": "10", "X-Rate-Limit-Remaining": "1", "X-Rate-Limit-Reset": reset}
        responses = [respond(status=503), respond(status=429, headers={"Retry-After": "1"}),
                     *[respond([app_json(APP_A)], next_url=page_url("/api/v1/apps", f"c{i}"), headers=low) for i in range(10)]]
        client, transport, _ = make_client(*responses, pacing=PacingPolicy(max_requests=4, min_interval_seconds=0))
        client.list_applications()
        self.assertEqual(len(transport.calls), 4)
        self.assertEqual(client.stats.attempts, 4)
        self.assertEqual(client.budget_remaining, 0)


class RateLimitTests(unittest.TestCase):
    def test_429_honours_retry_after_with_jitter(self):
        client, transport, sleep = make_client(respond(status=429, headers={"Retry-After": "2"}),
                                               respond([app_json(APP_A)]))
        listing = client.list_applications()
        self.assertEqual(listing.status, ResultStatus.COMPLETE)
        self.assertEqual(sleep.delays, [2.5])  # 2 s plus rng() = 0.5 jitter
        self.assertEqual(client.stats.rate_limited_responses, 1)
        self.assertEqual(client.stats.retries, 1)
        self.assertEqual(len(transport.calls), 2)

    def test_429_without_retry_after_uses_okta_reset_header(self):
        reset = int(NOW.timestamp()) + 10
        client, _, sleep = make_client(
            respond(status=429, headers={"X-Rate-Limit-Reset": str(reset), "X-Rate-Limit-Remaining": "0"}),
            respond([app_json(APP_A)]),
        )
        self.assertTrue(client.list_applications().complete)
        self.assertEqual(sleep.delays, [11.5])  # reset - now + 1, plus jitter

    def test_429_without_any_header_uses_jittered_backoff(self):
        client, _, sleep = make_client(respond(status=429), respond([]))
        client.list_applications()
        self.assertEqual(sleep.delays, [HttpPolicy().backoff_delay(0, lambda: 0.5)])

    def test_non_ascii_digit_rate_limit_headers_are_unusable_not_a_crash(self):
        for header in ("Retry-After", "X-Rate-Limit-Reset"):
            for value in ("\u00b2", "\u0665"):  # superscript two; Arabic-Indic five
                with self.subTest(header=header, value=value):
                    client, _, sleep = make_client(respond(status=429, headers={header: value}), respond([]))
                    self.assertTrue(client.list_applications().complete)
                    self.assertEqual(sleep.delays, [HttpPolicy().backoff_delay(0, lambda: 0.5)])
        reset = str(int(NOW.timestamp()) + 20)
        for value in ("\u00b2", "\u0665"):
            with self.subTest(header="X-Rate-Limit-Remaining", value=value):
                odd = {"X-Rate-Limit-Limit": "100", "X-Rate-Limit-Remaining": value, "X-Rate-Limit-Reset": reset}
                client, _, _ = make_client(respond([app_json(APP_A)], headers=odd))
                self.assertTrue(client.list_applications().complete)
                self.assertIsNone(client.stats.last_rate_limit_remaining)

    def test_excessive_wait_halts_instead_of_sleeping(self):
        client, transport, sleep = make_client(respond(status=429, headers={"Retry-After": "600"}))
        listing = client.list_applications()
        self.assertEqual(listing.status, ResultStatus.FAILED)
        self.assertEqual(listing.error_code, CollectorErrorCode.RATE_LIMITED)
        self.assertEqual(sleep.delays, [])
        self.assertIsNotNone(client.halted)
        client.get_application(APP_A)
        self.assertEqual(len(transport.calls), 1)

    def test_persistent_429_exhausts_bounded_retries_and_halts(self):
        policy = HttpPolicy(max_retries=2)
        client, transport, _ = make_client(*[respond(status=429, headers={"Retry-After": "1"})] * 3, policy=policy)
        listing = client.list_applications()
        self.assertEqual(listing.error_code, CollectorErrorCode.RATE_LIMITED)
        self.assertEqual(len(transport.calls), 3)
        self.assertIsNotNone(client.halted)

    def test_proactive_throttle_waits_for_reset_when_reserve_is_reached(self):
        reset = int(NOW.timestamp()) + 20
        low = {"X-Rate-Limit-Limit": "100", "X-Rate-Limit-Remaining": "15", "X-Rate-Limit-Reset": str(reset)}
        client, _, sleep = make_client(respond([app_json(APP_A)], next_url=page_url("/api/v1/apps", "c"), headers=low),
                                       respond([app_json(APP_B)]))
        self.assertTrue(client.list_applications().complete)
        self.assertEqual(sleep.delays, [21.0])  # reserve = 20% of 100 = 20 >= 15 remaining
        self.assertEqual(client.stats.throttle_pauses, 1)

    def test_no_throttle_while_headroom_remains(self):
        ample = {"X-Rate-Limit-Limit": "100", "X-Rate-Limit-Remaining": "80",
                 "X-Rate-Limit-Reset": str(int(NOW.timestamp()) + 20)}
        client, _, sleep = make_client(respond([app_json(APP_A)], next_url=page_url("/api/v1/apps", "c"), headers=ample),
                                       respond([]))
        client.list_applications()
        self.assertEqual(sleep.delays, [])

    def test_throttle_reset_too_far_away_halts(self):
        far = {"X-Rate-Limit-Limit": "100", "X-Rate-Limit-Remaining": "1",
               "X-Rate-Limit-Reset": str(int(NOW.timestamp()) + 3600)}
        client, transport, _ = make_client(respond([app_json(APP_A)], next_url=page_url("/api/v1/apps", "c"), headers=far))
        listing = client.list_applications()
        self.assertEqual(listing.status, ResultStatus.PARTIAL)
        self.assertEqual(listing.error_code, CollectorErrorCode.RATE_LIMITED)
        self.assertEqual(len(transport.calls), 1)

    def test_min_interval_paces_serial_requests(self):
        client, _, sleep = make_client(respond([app_json(APP_A)], next_url=page_url("/api/v1/apps", "c")), respond([]),
                                       pacing=PacingPolicy(min_interval_seconds=0.25))
        client.list_applications()
        self.assertEqual(sleep.delays, [0.25])


class ServerErrorAndTimeoutTests(unittest.TestCase):
    def test_5xx_is_retried_then_succeeds(self):
        for status in (500, 502, 503, 504):
            with self.subTest(status=status):
                client, transport, sleep = make_client(respond(status=status), respond([app_json(APP_A)]))
                self.assertTrue(client.list_applications().complete)
                self.assertEqual(len(transport.calls), 2)
                self.assertEqual(sleep.delays, [HttpPolicy().backoff_delay(0, lambda: 0.5)])

    def test_persistent_5xx_fails_without_halting(self):
        client, transport, sleep = make_client(*[respond(status=503)] * 4, respond(app_json(APP_A)))
        listing = client.list_applications()
        self.assertEqual(listing.status, ResultStatus.FAILED)
        self.assertEqual(listing.error_code, CollectorErrorCode.HTTP_ERROR)
        self.assertEqual(len(transport.calls), 4)  # 1 + max_retries (3)
        self.assertEqual(len(sleep.delays), 3)
        self.assertIsNone(client.halted)
        self.assertTrue(client.get_application(APP_A).complete)  # the session continues

    def test_client_errors_are_not_retried(self):
        client, transport, _ = make_client(respond({"errorCode": "E0000031"}, status=400))
        listing = client.list_applications()
        self.assertEqual(listing.error_code, CollectorErrorCode.HTTP_ERROR)
        self.assertEqual(len(transport.calls), 1)

    def test_timeouts_are_retried_then_reported_as_timeout(self):
        def timeout():
            try:
                raise TimeoutError("synthetic read timeout")
            except TimeoutError as exc:
                error = TransportError("TimeoutError contacting okta.synthetic.example")
                error.__cause__ = exc
                return error
        client, transport, sleep = make_client(*[timeout() for _ in range(4)])
        listing = client.list_applications()
        self.assertEqual(listing.status, ResultStatus.FAILED)
        self.assertEqual(listing.error_code, CollectorErrorCode.TIMEOUT)
        self.assertEqual(len(transport.calls), 4)
        self.assertEqual(client.stats.transport_errors, 4)

    def test_timeout_then_success(self):
        client, _, _ = make_client(TransportError("synthetic connection reset"), respond([app_json(APP_A)]))
        self.assertTrue(client.list_applications().complete)

    def test_non_timeout_transport_failure_is_http_error(self):
        client, _, _ = make_client(*[TransportError("synthetic connection reset")] * 4)
        self.assertEqual(client.list_applications().error_code, CollectorErrorCode.HTTP_ERROR)


class PartialPageTests(unittest.TestCase):
    def test_failure_on_a_later_page_is_partial_with_earlier_items(self):
        client, _, _ = make_client(respond([app_json(APP_A)], next_url=page_url("/api/v1/apps", "c1")),
                                   *[respond(status=503)] * 4)
        listing = client.list_applications()
        self.assertEqual(listing.status, ResultStatus.PARTIAL)
        self.assertEqual([a.okta_app_id for a in listing.items], [APP_A])
        self.assertEqual(listing.error_code, CollectorErrorCode.HTTP_ERROR)
        self.assertFalse(listing.complete)

    def test_non_array_page_is_partial(self):
        client, _, _ = make_client(respond([app_json(APP_A)], next_url=page_url("/api/v1/apps", "c1")),
                                   respond({"unexpected": "object"}))
        listing = client.list_applications()
        self.assertEqual(listing.status, ResultStatus.PARTIAL)
        self.assertEqual(listing.stop_reason, StopReason.MALFORMED_PAGE)

    def test_truncated_json_page_is_partial(self):
        client, _, _ = make_client(respond([app_json(APP_A)], next_url=page_url("/api/v1/apps", "c1")),
                                   respond(raw=b'[{"id": "0oaSYNTH'))
        self.assertEqual(client.list_applications().stop_reason, StopReason.MALFORMED_PAGE)

    def test_malformed_first_page_is_failed(self):
        client, _, _ = make_client(respond(raw=b"<html>synthetic</html>"))
        self.assertEqual(client.list_applications().status, ResultStatus.FAILED)

    def test_listing_for_a_deleted_app_is_failed_not_empty(self):
        client, _, _ = make_client(respond({"errorCode": "E0000007"}, status=404))
        listing = client.list_application_group_assignments(APP_A)
        self.assertEqual(listing.status, ResultStatus.FAILED)
        self.assertEqual(listing.stop_reason, StopReason.NOT_FOUND)


class MissingFieldTests(unittest.TestCase):
    def test_records_missing_required_fields_make_the_listing_partial(self):
        client, _, _ = make_client(respond([
            app_json(APP_A),
            {"label": "SYNTH no id", "status": "ACTIVE"},
            app_json(APP_B, status=None),
            app_json("not-an-okta-id!"),
            "not an object",
        ]))
        listing = client.list_applications()
        self.assertEqual(listing.status, ResultStatus.PARTIAL)
        self.assertEqual(listing.malformed_records, 4)
        self.assertEqual([a.okta_app_id for a in listing.items], [APP_A])
        self.assertEqual(listing.error_code, CollectorErrorCode.OTHER)

    def test_missing_optional_fields_become_none(self):
        client, _, _ = make_client(respond([{"id": APP_A, "status": "ACTIVE"}]))
        listing = client.list_applications()
        self.assertTrue(listing.complete)
        app = listing.items[0]
        self.assertIsNone(app.label)
        self.assertIsNone(app.sign_on_mode)
        self.assertIsNone(app.created)

    def test_group_without_name_is_an_unreadable_lookup(self):
        client, _, _ = make_client(respond({"id": GROUP_1, "type": "OKTA_GROUP", "profile": {}}))
        lookup = client.get_group(GROUP_1)
        self.assertEqual(lookup.status, ResultStatus.FAILED)
        self.assertFalse(lookup.found)

    def test_embedded_group_that_does_not_match_is_malformed(self):
        client, _, _ = make_client(respond([assignment_json(GROUP_1, embed=group_json(GROUP_2))]))
        listing = client.list_application_group_assignments(APP_A, expand_groups=True)
        self.assertEqual(listing.malformed_records, 1)
        self.assertEqual(listing.status, ResultStatus.PARTIAL)


class AssignmentTests(unittest.TestCase):
    def test_lists_assignments_with_embedded_groups(self):
        client, transport, _ = make_client(respond([
            assignment_json(GROUP_1, priority=1, embed=group_json(GROUP_1)),
            assignment_json(GROUP_2, embed=group_json(GROUP_2, group_type="APP_GROUP", ad=True)),
        ]))
        listing = client.list_application_group_assignments(APP_A, expand_groups=True)
        self.assertTrue(listing.complete)
        self.assertEqual(_query(transport.calls[0]["url"]), {"limit": "200", "expand": "group"})
        self.assertEqual(urlsplit(transport.calls[0]["url"]).path, f"/api/v1/apps/{APP_A}/groups")
        first, second = listing.items
        self.assertEqual((first.okta_app_id, first.okta_group_id, first.priority), (APP_A, GROUP_1, 1))
        self.assertEqual(second.group.directory_object_guid_unverified, SYNTHETIC_GUID)

    def test_duplicate_assignments_are_dropped_and_mark_the_listing_partial(self):
        client, _, _ = make_client(
            respond([assignment_json(GROUP_1), assignment_json(GROUP_2)], next_url=page_url(f"/api/v1/apps/{APP_A}/groups", "c")),
            respond([assignment_json(GROUP_2), assignment_json(GROUP_3)]),
        )
        listing = client.list_application_group_assignments(APP_A)
        self.assertEqual([a.okta_group_id for a in listing.items], [GROUP_1, GROUP_2, GROUP_3])
        self.assertEqual(listing.duplicates_dropped, 1)
        self.assertEqual(listing.status, ResultStatus.PARTIAL)
        self.assertEqual(listing.error_code, CollectorErrorCode.PAGING_INTERRUPTED)
        self.assertTrue(listing.notes)

    def test_ids_are_validated_before_use_in_urls(self):
        client, transport, _ = make_client()
        for bad in ("../users", "0oa\"x", "", "a" * 65, 'x" or 1 eq 1'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                client.list_application_group_assignments(bad)
        self.assertEqual(transport.calls, [])


class GroupTests(unittest.TestCase):
    def test_ad_imported_group_carries_stable_directory_ids(self):
        client, transport, _ = make_client(respond(group_json(GROUP_1, group_type="APP_GROUP", ad=True)))
        lookup = client.get_group(GROUP_1)
        self.assertTrue(lookup.found and lookup.complete)
        group = lookup.item
        self.assertEqual(group.group_type, GroupType.APP_GROUP)
        self.assertEqual(group.source_app_id, AD_INTEGRATION)
        self.assertEqual(group.directory_object_guid_unverified, SYNTHETIC_GUID)
        self.assertEqual(group.directory_object_sid, SYNTHETIC_SID)
        self.assertEqual(group.sam_account_name, "SYNTH-GROUP")
        self.assertEqual(urlsplit(transport.calls[0]["url"]).path, f"/api/v1/groups/{GROUP_1}")

    def test_okta_mastered_group_has_no_directory_attributes(self):
        raw = group_json(GROUP_1, ad=True)  # attributes present but type OKTA_GROUP
        client, _, _ = make_client(respond(raw))
        group = client.get_group(GROUP_1).item
        self.assertIsNone(group.directory_object_guid_unverified)
        self.assertIsNone(group.source_app_id)

    def test_unknown_group_is_a_definite_not_found(self):
        client, _, _ = make_client(respond({"errorCode": "E0000007"}, status=404))
        lookup = client.get_group(GROUP_1)
        self.assertEqual((lookup.found, lookup.status), (False, ResultStatus.COMPLETE))

    def test_unrecognised_external_id_is_not_guessed(self):
        for value in (None, "", "not base64!", "c3ludGhldGlj"):  # last decodes to 9 bytes
            with self.subTest(value=value):
                self.assertIsNone(decode_object_guid(value))


class MemberTests(unittest.TestCase):
    def test_members_keep_only_id_and_status(self):
        client, _, _ = make_client(respond([member_json(USER_1), member_json(USER_2, status="SUSPENDED")]))
        listing = client.list_group_members(GROUP_1)
        self.assertTrue(listing.complete)
        self.assertEqual([(m.okta_user_id, m.status) for m in listing.items], [(USER_1, "ACTIVE"), (USER_2, "SUSPENDED")])
        self.assertNotIn("synthetic.example", repr(listing))

    def test_member_cap_stops_partial(self):
        client, _, _ = make_client(respond([member_json(USER_1), member_json(USER_2), member_json(USER_3)]))
        listing = client.list_group_members(GROUP_1, max_members=2)
        self.assertEqual(listing.status, ResultStatus.PARTIAL)
        self.assertEqual(listing.stop_reason, StopReason.ITEM_LIMIT)
        self.assertEqual(len(listing.items), 2)

    def test_exactly_the_cap_is_complete(self):
        client, _, _ = make_client(respond([member_json(USER_1), member_json(USER_2)]))
        self.assertTrue(client.list_group_members(GROUP_1, max_members=2).complete)


class BudgetTests(unittest.TestCase):
    def test_budget_stops_paging_and_halts(self):
        client, transport, _ = make_client(
            respond([app_json(APP_A)], next_url=page_url("/api/v1/apps", "c1")),
            respond([app_json(APP_B)], next_url=page_url("/api/v1/apps", "c2")),
            respond([app_json(APP_C)]),
            pacing=PacingPolicy(max_requests=2, min_interval_seconds=0),
        )
        listing = client.list_applications()
        self.assertEqual(listing.status, ResultStatus.PARTIAL)
        self.assertEqual(listing.stop_reason, StopReason.BUDGET_EXHAUSTED)
        self.assertEqual(len(listing.items), 2)
        self.assertEqual(len(transport.calls), 2)
        self.assertEqual(client.budget_remaining, 0)

    def test_retries_count_against_the_budget(self):
        client, transport, _ = make_client(respond(status=503), respond(status=503), respond([]),
                                           pacing=PacingPolicy(max_requests=2, min_interval_seconds=0))
        listing = client.list_applications()
        self.assertEqual(listing.error_code, CollectorErrorCode.PAGING_INTERRUPTED)
        self.assertEqual(len(transport.calls), 2)

    def test_pacing_policy_is_bounded(self):
        for kwargs in ({"max_requests": 0}, {"max_requests": 10_001}, {"max_wait_seconds": 301},
                       {"min_interval_seconds": -1}, {"rate_limit_reserve_fraction": 1.0}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                PacingPolicy(**kwargs)


class ProbeTests(unittest.TestCase):
    def test_probe_is_one_bounded_read_reporting_only_counts(self):
        client, transport, _ = make_client(
            respond([app_json(APP_A, label="SYNTH Secret Project")],
                    headers={"X-Rate-Limit-Limit": "100", "X-Rate-Limit-Remaining": "99"}),
            pacing=PacingPolicy(max_requests=1, min_interval_seconds=0))
        result = client.probe()
        self.assertTrue(result.ok)
        self.assertEqual((result.http_status, result.items_returned), (200, 1))
        self.assertEqual(result.granted_scopes, tuple(sorted(grant().scopes)))
        self.assertEqual((result.rate_limit_remaining, result.rate_limit_limit), (99, 100))
        self.assertEqual(_query(transport.calls[0]["url"]), {"limit": "1"})
        self.assertNotIn("Secret Project", repr(result))
        self.assertNotIn(APP_A, repr(result))

    def test_probe_never_exceeds_one_request(self):
        client, transport, _ = make_client(respond(status=503), respond([]),
                                           pacing=PacingPolicy(max_requests=1, min_interval_seconds=0))
        result = client.probe()
        self.assertFalse(result.ok)
        self.assertEqual(len(transport.calls), 1)

    def test_probe_requires_a_budget_of_one(self):
        client, _, _ = make_client()
        with self.assertRaises(ValueError):
            client.probe()

    def test_probe_reports_refused_credentials(self):
        client, _, _ = make_client(respond(status=401), pacing=PacingPolicy(max_requests=1, min_interval_seconds=0))
        result = client.probe()
        self.assertFalse(result.ok)
        self.assertEqual(result.http_status, 401)


class ReadOnlySafetyTests(unittest.TestCase):
    def test_client_has_no_mutating_methods(self):
        for name in ("post", "put", "patch", "delete", "send_mutation", "request", "create", "update",
                     "deactivate", "unassign", "remove"):
            with self.subTest(name=name):
                self.assertFalse(any(attr.lower().startswith(name) for attr in dir(OktaReadOnlyClient)
                                     if not attr.startswith("_")))

    def test_integration_package_never_imports_mutation_or_raw_network_code(self):
        forbidden = {"app.core.http_mutation", "app.core.safety", "subprocess", "socket", "urllib.request",
                     "http.client", "requests", "httpx", "ssl"}
        for path in OKTA_PACKAGE.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(a.name for a in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module)
            with self.subTest(path=path.name):
                self.assertEqual(imported & forbidden, set())

    def test_integration_package_names_no_unsafe_http_method(self):
        for path in OKTA_PACKAGE.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            literals = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
            with self.subTest(path=path.name):
                self.assertEqual(literals & {"POST", "PUT", "PATCH", "DELETE"}, set())

    def test_synthetic_mode_cannot_reach_a_real_host(self):
        with self.assertRaises(NetworkPolicyError):
            OktaReadOnlyClient(org_url=SYNTHETIC_OKTA_URL, mode=ExecutionMode.LOCAL_SYNTHETIC,
                               http_policy=HttpPolicy(), credentials=StaticGrantProvider(grant()))

    def test_org_url_must_be_a_bare_https_origin(self):
        for url in ("http://okta.synthetic.example", "https://okta.synthetic.example/api",
                    "https://user:pw@okta.synthetic.example", "https://okta.synthetic.example?x=1", "okta"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                OktaReadOnlyClient(org_url=url, mode=ExecutionMode.READ_ONLY_PRODUCTION,
                                   http_policy=HttpPolicy(), credentials=StaticGrantProvider(grant()))

    def test_executor_refuses_an_underlying_client_that_retries(self):
        http = ReadOnlyHttpClient(mode=ExecutionMode.READ_ONLY_PRODUCTION, http_policy=HttpPolicy(),
                                  allowed_hosts=["okta.synthetic.example"], transport=GetOnlyTransport())
        with self.assertRaises(ValueError):
            OktaRequestExecutor(http=http, pacing=PacingPolicy(), max_retries=3, backoff=HttpPolicy())

    def test_logs_never_contain_token_or_query(self):
        with captured_logs() as stream:
            client, _, _ = make_client(respond([app_json(APP_A)]), logger=logging.getLogger("ogwa.okta"))
            client.list_applications(status=AppStatus.ACTIVE)
        output = stream.getvalue()
        self.assertIn("okta.listing", output)
        self.assertNotIn(SYNTHETIC_ACCESS_TOKEN, output)
        self.assertNotIn("status eq", output)
        self.assertNotIn("limit=", output)


class _DuplicateLinkHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"[]"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Link", '<http://127.0.0.1/api/v1/apps>; rel="self"')
        self.send_header("link", '<http://127.0.0.1/api/v1/apps?after=next>; rel="next"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class TransportHeaderTests(unittest.TestCase):
    def test_combine_headers_keeps_every_repeated_field(self):
        combined = combine_headers([("Link", "<a>; rel=\"self\""), ("link", "<b>; rel=\"next\""), ("X", "1")])
        self.assertEqual(combined, {"link": '<a>; rel="self", <b>; rel="next"', "x": "1"})

    def test_stdlib_transport_keeps_both_link_headers(self):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _DuplicateLinkHandler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            response = StdlibTransport().send(
                "GET", f"http://127.0.0.1:{server.server_address[1]}/api/v1/apps", {}, None,
                connect_timeout=1.0, read_timeout=1.0, max_response_bytes=1024)
        finally:
            server.shutdown()
            server.server_close()
        self.assertIn('rel="self"', response.header("Link"))
        self.assertIn('rel="next"', response.header("Link"))
        self.assertEqual(json.loads(response.body), [])


if __name__ == "__main__":
    unittest.main()
