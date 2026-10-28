"""System Log usage windows, aggregation, domain evidence conversion, run summaries.

Synthetic data and fake transports only.
"""

import unittest
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlsplit

from app.domain.actors import Actor, ActorKind
from app.domain.collection import CollectorErrorCode, CollectorRun
from app.domain.errors import InvalidRecord
from app.domain.evidence import EvidenceSource, ResultStatus
from app.domain.ids import IdKind, check_id, new_id
from app.domain.model import OktaGroupType
from app.domain.policy import LifecyclePolicy
from app.core.modes import ExecutionMode
from app.integrations.okta.evidence import (
    StableIdResolver,
    application_evidence,
    assignment_evidence,
    group_evidence,
    summarize_run,
    usage_evidence,
)
from app.integrations.okta.normalize import OBJECT_GUID_DECODING_VERIFIED
from app.integrations.okta.usage import (
    RETIREMENT_USAGE_WINDOW,
    USAGE_CAVEATS,
    ApplicationUsageEvidence,
    UsageSignal,
    UsageStrategy,
    collect_application_usage,
    slice_window,
    window_limitations,
)
from tests.okta_fixtures import (
    SYNTHETIC_SID,
    APP_A,
    APP_B,
    APP_C,
    GROUP_1,
    GROUP_2,
    GROUP_3,
    NOW,
    SYNTHETIC_GUID,
    USER_1,
    USER_2,
    USER_3,
    app_json,
    assignment_json,
    event_json,
    group_json,
    make_client,
    page_url,
    respond,
)

# A window that lies inside retention and outside the ingestion lag.
END = NOW - timedelta(hours=1)
START = END - timedelta(days=14)
IDS = StableIdResolver("okta.synthetic.example")


def _query(url):
    return {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}


def _collect(*responses, apps=(APP_A,), start=START, end=END, chunk=timedelta(days=7), now=NOW,
             strategy=UsageStrategy.PER_APPLICATION, policy=None):
    client, transport, sleep = make_client(*responses, policy=policy)
    result = collect_application_usage(client, apps, start, end, now=now, chunk=chunk, strategy=strategy)
    return result, client, transport


class WindowTests(unittest.TestCase):
    def test_slices_cover_the_window_exactly(self):
        slices = slice_window(START, END, timedelta(days=5))
        self.assertEqual(slices[0][0], START)
        self.assertEqual(slices[-1][1], END)
        self.assertEqual(len(slices), 3)
        for (a, b), (c, _) in zip(slices, slices[1:]):
            self.assertEqual(b, c)

    def test_tiny_chunks_are_refused(self):
        with self.assertRaises(ValueError):
            slice_window(START, END, timedelta(minutes=5))

    def test_window_beyond_retention_or_inside_ingestion_lag_is_incomplete(self):
        self.assertEqual(window_limitations(START, END, NOW), [])
        self.assertEqual(len(window_limitations(NOW - timedelta(days=91), END, NOW)), 1)
        self.assertEqual(len(window_limitations(START, NOW - timedelta(minutes=2), NOW)), 1)

    def test_exact_policy_window_cannot_be_complete_with_default_retention(self):
        # LifecyclePolicy.min_usage_window is 90 days and System Log retention is 90 days:
        # any window that also clears the ingestion lag starts before the horizon.
        end = NOW - timedelta(minutes=10)
        self.assertTrue(window_limitations(end - timedelta(days=90), end, NOW))

    def test_invalid_windows_are_refused_before_any_request(self):
        client, transport, _ = make_client()
        naive = datetime(2026, 8, 1, 0, 0)
        cases = [
            dict(okta_app_ids=[APP_A], window_start=END, window_end=START),
            dict(okta_app_ids=[APP_A], window_start=START, window_end=NOW + timedelta(minutes=1)),
            dict(okta_app_ids=[APP_A], window_start=naive, window_end=END),
            dict(okta_app_ids=[], window_start=START, window_end=END),
            dict(okta_app_ids=['0oa" or true'], window_start=START, window_end=END),
        ]
        for kwargs in cases:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                collect_application_usage(client, now=NOW, **kwargs)
        self.assertEqual(transport.calls, [])


class UsageAggregationTests(unittest.TestCase):
    def test_window_with_no_events_is_complete_zero_but_carries_caveats(self):
        result, _, transport = _collect(respond([]), respond([]))
        usage = result.for_app(APP_A)
        self.assertTrue(usage.evidence_complete)
        self.assertEqual((usage.sign_in_count, usage.unique_user_count, usage.last_observed_sign_in), (0, 0, None))
        self.assertEqual((usage.slices_complete, usage.slices_total), (2, 2))
        self.assertEqual(usage.caveats, USAGE_CAVEATS)
        self.assertIn("not evidence that the application is unused", " ".join(usage.caveats))
        self.assertEqual(result.status, ResultStatus.COMPLETE)
        self.assertEqual(len(transport.calls), 2)

    def test_queries_are_bounded_filtered_and_ascending(self):
        _, _, transport = _collect(respond([]), respond([]))
        first = _query(transport.calls[0]["url"])
        self.assertEqual(urlsplit(transport.calls[0]["url"]).path, "/api/v1/logs")
        self.assertEqual(first["since"], START.strftime("%Y-%m-%dT%H:%M:%S.000Z"))
        self.assertEqual(first["until"], (START + timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000Z"))
        self.assertEqual(first["sortOrder"], "ASCENDING")
        self.assertEqual(first["limit"], "1000")
        self.assertEqual(first["filter"], 'eventType eq "user.authentication.sso" and outcome.result eq "SUCCESS" '
                                          f'and target.id eq "{APP_A}"')
        self.assertEqual(_query(transport.calls[1]["url"])["until"], END.strftime("%Y-%m-%dT%H:%M:%S.000Z"))

    def test_counts_users_and_last_sign_in_across_pages_and_slices(self):
        t1, t2, t3 = START + timedelta(days=1), START + timedelta(days=2), START + timedelta(days=10)
        result, _, _ = _collect(
            respond([event_json(APP_A, USER_1, t1), event_json(APP_A, USER_2, t2)],
                    next_url=page_url("/api/v1/logs", "c1")),
            respond([event_json(APP_A, USER_1, t2)]),
            respond([event_json(APP_A, USER_3, t3)]),
        )
        usage = result.for_app(APP_A)
        self.assertTrue(usage.evidence_complete)
        self.assertEqual(usage.sign_in_count, 4)
        self.assertEqual(usage.unique_user_count, 3)
        self.assertEqual(usage.last_observed_sign_in, t3)

    def test_empty_page_ends_a_bounded_query_even_with_a_next_link(self):
        result, _, transport = _collect(respond([], next_url=page_url("/api/v1/logs", "c1")), respond([]))
        self.assertTrue(result.for_app(APP_A).evidence_complete)
        self.assertEqual(len(transport.calls), 2)  # one per slice; the next link was not followed

    def test_failed_slice_makes_evidence_incomplete(self):
        result, _, _ = _collect(respond([event_json(APP_A, USER_1, START + timedelta(days=1))]),
                                *[respond(status=503)] * 4)
        usage = result.for_app(APP_A)
        self.assertFalse(usage.evidence_complete)
        self.assertEqual((usage.slices_complete, usage.slices_total), (1, 2))
        self.assertTrue(any("FAILED" in r for r in usage.incomplete_reasons))
        self.assertEqual(usage.sign_in_count, 1)  # what was seen is kept, but flagged
        self.assertEqual(result.status, ResultStatus.PARTIAL)

    def test_rate_limit_halt_marks_remaining_slices_without_sending(self):
        result, client, transport = _collect(respond(status=429, headers={"Retry-After": "900"}), apps=(APP_A, APP_B))
        self.assertEqual(len(transport.calls), 1)
        self.assertIsNotNone(client.halted)
        for app in (APP_A, APP_B):
            self.assertFalse(result.for_app(app).evidence_complete)
        self.assertEqual(result.status, ResultStatus.FAILED)

    def test_events_without_actor_make_unique_users_a_lower_bound(self):
        result, _, _ = _collect(respond([event_json(APP_A, None, START + timedelta(days=1))]), respond([]))
        usage = result.for_app(APP_A)
        self.assertEqual((usage.sign_in_count, usage.unique_user_count), (1, 0))
        self.assertFalse(usage.evidence_complete)
        self.assertTrue(any("lower bound" in r for r in usage.incomplete_reasons))

    def test_unreadable_event_makes_the_slice_partial(self):
        result, _, _ = _collect(respond([{"eventType": "user.authentication.sso"}]), respond([]))
        self.assertFalse(result.for_app(APP_A).evidence_complete)
        self.assertEqual(result.malformed_events, 1)

    def test_events_outside_the_slice_are_not_counted(self):
        result, _, _ = _collect(respond([event_json(APP_A, USER_1, START - timedelta(days=3))]), respond([]))
        usage = result.for_app(APP_A)
        self.assertEqual(usage.sign_in_count, 0)
        self.assertFalse(usage.evidence_complete)

    def test_retention_limitation_is_reported(self):
        start = NOW - timedelta(days=95)
        result, _, _ = _collect(*[respond([])] * 2, start=start, end=start + timedelta(days=10),
                                chunk=timedelta(days=10))
        usage = result.for_app(APP_A)
        self.assertFalse(usage.evidence_complete)
        self.assertTrue(any("retention" in r for r in usage.incomplete_reasons))

    def test_org_wide_strategy_aggregates_requested_apps_only(self):
        when = START + timedelta(days=1)
        result, _, transport = _collect(
            respond([event_json(APP_A, USER_1, when), event_json(APP_B, USER_2, when),
                     event_json(APP_C, USER_3, when), event_json(APP_A, USER_2, when)]),
            respond([]),
            apps=(APP_A, APP_B), strategy=UsageStrategy.ORG_WIDE,
        )
        self.assertEqual(len(transport.calls), 2)  # one stream per slice, not per app
        self.assertNotIn("target.id", _query(transport.calls[0]["url"])["filter"])
        self.assertEqual(result.for_app(APP_A).sign_in_count, 2)
        self.assertEqual(result.for_app(APP_B).sign_in_count, 1)
        self.assertIsNone(result.for_app(APP_C))
        self.assertEqual(result.events_unattributed, 1)

    def test_usage_results_hold_no_user_ids(self):
        result, _, _ = _collect(respond([event_json(APP_A, USER_1, START + timedelta(days=1))]), respond([]))
        self.assertNotIn(USER_1, repr(result))


class EvidenceConversionTests(unittest.TestCase):
    def test_stable_ids_are_valid_deterministic_and_tenant_scoped(self):
        a = IDS.application(APP_A)
        check_id(a, IdKind.OKTA_APPLICATION, "id")
        self.assertEqual(a, StableIdResolver("OKTA.synthetic.example").application(APP_A))
        self.assertNotEqual(a, StableIdResolver("other.synthetic.example").application(APP_A))
        self.assertNotEqual(IDS.assignment(APP_A, GROUP_1), IDS.assignment(APP_A, GROUP_2))
        check_id(IDS.usage(APP_A), IdKind.USAGE_OBSERVATION, "id")

    def test_application_evidence_from_a_listing(self):
        client, _, _ = make_client(respond([{"id": APP_A, "status": "INACTIVE"}]))
        listing = client.list_applications()
        app = application_evidence(listing.items[0], ids=IDS, observed_at=NOW, scope=listing.scope, status=listing.status)
        self.assertEqual(app.label, APP_A)  # display-only fallback
        self.assertEqual(app.sign_on_mode, "UNKNOWN")
        self.assertEqual(app.provenance.source, EvidenceSource.OKTA_API)
        self.assertTrue(app.provenance.decision_grade)

    def test_partial_listing_never_yields_decision_grade_evidence(self):
        client, _, _ = make_client(respond([app_json(APP_A)], next_url=page_url("/api/v1/apps", "c")),
                                   *[respond(status=503)] * 4)
        listing = client.list_applications()
        app = application_evidence(listing.items[0], ids=IDS, observed_at=NOW, scope=listing.scope, status=listing.status)
        self.assertFalse(app.provenance.decision_grade)

    def test_unverified_object_guid_never_reaches_domain_evidence(self):
        # D23/D30: unverified until P11 proves it against a known AD-backed Okta group.
        self.assertIs(OBJECT_GUID_DECODING_VERIFIED, False)
        client, _, _ = make_client(respond(group_json(GROUP_1, group_type="APP_GROUP", ad=True)))
        lookup = client.get_group(GROUP_1)
        self.assertEqual(lookup.item.directory_object_guid_unverified, SYNTHETIC_GUID)  # normalized, labelled
        group = group_evidence(lookup.item, ids=IDS, observed_at=NOW, scope=lookup.scope, status=lookup.status)
        self.assertEqual(group.group_type, OktaGroupType.APP_GROUP)
        self.assertIsNone(group.directory_external_id)
        self.assertNotIn(SYNTHETIC_GUID, repr(group))
        self.assertEqual(group.directory_qualified_name, "SYNTH\\SYNTH-GROUP")

    def test_okta_directory_sid_is_kept_as_unverified_source_metadata(self):
        # Owner decision before P09 (migration 0008): persisted, labelled unverified (D37).
        client, _, _ = make_client(respond(group_json(GROUP_1, group_type="APP_GROUP", ad=True)))
        lookup = client.get_group(GROUP_1)
        group = group_evidence(lookup.item, ids=IDS, observed_at=NOW, scope=lookup.scope, status=lookup.status)
        self.assertEqual(group.directory_object_sid_unverified, SYNTHETIC_SID)
        self.assertEqual(group.provenance.observed_at, NOW)  # the observation's own provenance and freshness
        self.assertEqual(group.material()["directory_object_sid_unverified"], SYNTHETIC_SID)

    def test_okta_group_evidence_has_no_directory_attributes(self):
        client, _, _ = make_client(respond(group_json(GROUP_1)))
        lookup = client.get_group(GROUP_1)
        group = group_evidence(lookup.item, ids=IDS, observed_at=NOW, scope=lookup.scope, status=lookup.status)
        self.assertIsNone(group.directory_external_id)
        self.assertIsNone(group.directory_object_sid_unverified)

    def test_absence_is_recorded_only_from_a_complete_listing(self):
        client, _, _ = make_client(respond([assignment_json(GROUP_1)]))
        complete = client.list_application_group_assignments(APP_A)
        records = assignment_evidence(complete, APP_A, ids=IDS, observed_at=NOW, previously_present=[GROUP_1, GROUP_2])
        self.assertEqual({(r.okta_group_id, r.present) for r in records},
                         {(IDS.group(GROUP_1), True), (IDS.group(GROUP_2), False)})

        client, _, _ = make_client(
            respond([assignment_json(GROUP_1)], next_url=page_url(f"/api/v1/apps/{APP_A}/groups", "c")),
            *[respond(status=503)] * 4)
        partial = client.list_application_group_assignments(APP_A)
        records = assignment_evidence(partial, APP_A, ids=IDS, observed_at=NOW, previously_present=[GROUP_1, GROUP_3])
        self.assertEqual([(r.okta_group_id, r.present) for r in records], [(IDS.group(GROUP_1), True)])
        self.assertFalse(records[0].provenance.decision_grade)

    def test_usage_evidence_for_an_empty_window(self):
        result, _, _ = _collect(respond([]), respond([]))
        obs = usage_evidence(result.for_app(APP_A), ids=IDS, observed_at=NOW)
        self.assertEqual((obs.event_count, obs.distinct_user_count, obs.last_activity_at), (0, 0, None))
        self.assertEqual(obs.provenance.source, EvidenceSource.OKTA_SYSTEM_LOG)
        self.assertEqual(obs.provenance.result_status, ResultStatus.COMPLETE)
        self.assertEqual(obs.window, END - START)

    def test_incomplete_usage_becomes_partial_provenance(self):
        result, _, _ = _collect(respond([]), *[respond(status=503)] * 4)
        obs = usage_evidence(result.for_app(APP_A), ids=IDS, observed_at=NOW)
        self.assertEqual(obs.provenance.result_status, ResultStatus.PARTIAL)
        self.assertFalse(obs.provenance.decision_grade)

    def test_usage_evidence_cannot_be_observed_before_the_window_ends(self):
        result, _, _ = _collect(respond([]), respond([]))
        with self.assertRaises(InvalidRecord):
            usage_evidence(result.for_app(APP_A), ids=IDS, observed_at=END - timedelta(minutes=1))


class RetentionDecisionTests(unittest.TestCase):
    """Decision D27: the 90-day lifecycle window stays. Native System Log
    retention may give a shorter low-usage review signal, never a complete 90-day window."""

    def test_lifecycle_window_is_unchanged_at_90_days(self):
        self.assertEqual(LifecyclePolicy().min_usage_window, timedelta(days=90))
        self.assertEqual(RETIREMENT_USAGE_WINDOW, LifecyclePolicy().min_usage_window)

    def test_complete_shorter_window_is_a_review_signal_only(self):
        start = END - timedelta(days=30)
        result, _, _ = _collect(*[respond([])] * 5, start=start)
        usage = result.for_app(APP_A)
        self.assertTrue(usage.evidence_complete)
        self.assertIs(usage.signal, UsageSignal.REVIEW_SIGNAL_ONLY)
        obs = usage_evidence(usage, ids=IDS, observed_at=NOW)
        self.assertTrue(obs.provenance.decision_grade)
        self.assertLess(obs.window, LifecyclePolicy().min_usage_window)  # the lifecycle refuses it

    def test_native_90_day_window_cannot_be_complete(self):
        end = NOW - timedelta(minutes=10)
        result, _, _ = _collect(*[respond([])] * 13, start=end - timedelta(days=90), end=end)
        usage = result.for_app(APP_A)
        self.assertFalse(usage.evidence_complete)
        self.assertIs(usage.signal, UsageSignal.INCOMPLETE)
        self.assertTrue(any("retention" in r for r in usage.incomplete_reasons))
        self.assertFalse(usage_evidence(usage, ids=IDS, observed_at=NOW).provenance.decision_grade)

    def test_only_complete_full_window_evidence_covers_retirement(self):
        # Unreachable from native retention; shown for the classification only.
        full = ApplicationUsageEvidence(
            okta_app_id=APP_A, window_start=END - timedelta(days=90), window_end=END, sign_in_count=0,
            unique_user_count=0, last_observed_sign_in=None, evidence_complete=True, incomplete_reasons=(),
            slices_complete=13, slices_total=13)
        self.assertIs(full.signal, UsageSignal.COVERS_RETIREMENT_WINDOW)


class RunSummaryTests(unittest.TestCase):
    def _run_id(self):
        return new_id(IdKind.COLLECTOR_RUN)

    def test_complete_session_summarizes_to_a_complete_outcome(self):
        client, _, _ = make_client(respond([app_json(APP_A), app_json(APP_B)]), respond(group_json(GROUP_1)))
        results = [client.list_applications(), client.get_group(GROUP_1)]
        summary = summarize_run(client, collector="okta-apps", started_at=NOW, finished_at=NOW, results=results)
        self.assertEqual(summary.status, ResultStatus.COMPLETE)
        self.assertEqual((summary.records_observed, summary.requests_attempted, summary.results_complete), (3, 2, 2))
        outcome = summary.to_outcome(self._run_id())
        self.assertEqual(outcome.status, ResultStatus.COMPLETE)
        self.assertIsNone(outcome.error_code)

    def test_halted_session_summarizes_with_the_halting_reason(self):
        client, _, _ = make_client(respond([app_json(APP_A)], next_url=page_url("/api/v1/apps", "c")),
                                   respond(status=429, headers={"Retry-After": "900"}))
        results = [client.list_applications(), client.get_group(GROUP_1)]
        summary = summarize_run(client, collector="okta-apps", started_at=NOW, finished_at=NOW, results=results)
        self.assertEqual(summary.status, ResultStatus.PARTIAL)
        self.assertTrue(summary.halted)
        self.assertEqual(summary.error_code, CollectorErrorCode.RATE_LIMITED)
        outcome = summary.to_outcome(self._run_id())
        self.assertEqual(outcome.error_code, CollectorErrorCode.RATE_LIMITED)
        self.assertLessEqual(len(outcome.error_summary), 300)

    def test_usage_collection_summary(self):
        result, client, _ = _collect(respond([]), *[respond(status=503)] * 4)
        summary = summarize_run(client, collector="okta-usage", started_at=NOW, finished_at=NOW, results=[result])
        self.assertEqual(summary.status, ResultStatus.PARTIAL)
        self.assertEqual(summary.error_code, CollectorErrorCode.HTTP_ERROR)
        self.assertEqual(summary.server_errors, 4)
        self.assertEqual(summary.retries, 3)

    def test_empty_session_is_failed(self):
        client, _, _ = make_client()
        summary = summarize_run(client, collector="okta-apps", started_at=NOW, finished_at=NOW, results=[])
        self.assertEqual(summary.status, ResultStatus.FAILED)
        self.assertIsNotNone(summary.to_outcome(self._run_id()).error_code)

    def test_summary_fits_a_domain_collector_run(self):
        run = CollectorRun(id=self._run_id(), collector="okta-usage", collector_version="okta-readonly/0.1.0",
                           source=EvidenceSource.OKTA_SYSTEM_LOG, mode=ExecutionMode.READ_ONLY_PRODUCTION,
                           scope="okta:logs:sso", started_at=NOW, started_by=Actor(ActorKind.SYSTEM, "collector/okta-usage"))
        result, client, _ = _collect(respond([]), respond([]))
        summary = summarize_run(client, collector=run.collector, started_at=run.started_at, finished_at=NOW, results=[result])
        self.assertEqual(summary.to_outcome(run.id).records_observed, 1)


if __name__ == "__main__":
    unittest.main()
