import ast
import unittest
from pathlib import Path

from app.core.errors import MutationBlockedError
from app.core.http_client import HttpPolicy, HttpResponse, ReadOnlyHttpClient
from app.core.http_mutation import MutatingHttpClient
from app.core.modes import ExecutionMode
from app.core.safety import (
    MutationCapableService,
    MutationDecision,
    MutationPolicy,
    MutationRequest,
)
from tests.fakes import SYNTHETIC_OKTA_HOST, SYNTHETIC_OKTA_URL, FakeTransport

REPO_ROOT = Path(__file__).resolve().parents[1]

# Modules (repo-relative, forward slashes) reviewed and approved to import the mutating
# HTTP client. Adding to this set is a deliberate, reviewable change.
APPROVED_MUTATING_IMPORTERS: frozenset[str] = frozenset()

REAL_TARGET = MutationRequest(system="ad", action="remove_group_member", target="SYNTH-GROUP-001")
SYNTHETIC_TARGET = MutationRequest(
    system="ad", action="remove_group_member", target="SYNTH-GROUP-002", target_is_synthetic=True
)


class _ExampleService(MutationCapableService):
    def __init__(self, *, mutation_policy):
        super().__init__(mutation_policy=mutation_policy)
        self.calls = 0

    def remove(self, request):
        return self._perform(request, self._do_remove)

    def _do_remove(self):
        self.calls += 1
        return "removed"


class MutationPolicyInjectionTests(unittest.TestCase):
    def test_mutation_capable_service_requires_explicit_policy(self):
        with self.assertRaises(TypeError):
            _ExampleService()  # type: ignore[call-arg]
        for bogus in (None, "READ_ONLY_PRODUCTION", ExecutionMode.LOCAL_SYNTHETIC, object()):
            with self.subTest(bogus=bogus), self.assertRaises(TypeError):
                _ExampleService(mutation_policy=bogus)

    def test_policy_cannot_be_constructed_directly(self):
        with self.assertRaises(TypeError):
            MutationPolicy(ExecutionMode.LOCAL_SYNTHETIC)
        with self.assertRaises(TypeError):
            MutationPolicy(ExecutionMode.LOCAL_SYNTHETIC, _token=object())


class MutationDecisionTests(unittest.TestCase):
    def test_read_only_mode_blocks_and_never_runs_operation(self):
        service = _ExampleService(mutation_policy=MutationPolicy.for_mode(ExecutionMode.READ_ONLY_PRODUCTION))
        for request in (REAL_TARGET, SYNTHETIC_TARGET):
            with self.subTest(request=request), self.assertRaises(MutationBlockedError):
                service.remove(request)
        self.assertEqual(service.calls, 0)

    def test_dry_run_plans_but_never_runs_operation(self):
        service = _ExampleService(mutation_policy=MutationPolicy.for_mode(ExecutionMode.DRY_RUN_MUTATION))
        outcome = service.remove(REAL_TARGET)
        self.assertIs(outcome.decision, MutationDecision.PLAN_ONLY)
        self.assertFalse(outcome.executed)
        self.assertEqual(service.calls, 0)

    def test_synthetic_mode_blocks_real_targets(self):
        service = _ExampleService(mutation_policy=MutationPolicy.for_mode(ExecutionMode.LOCAL_SYNTHETIC))
        with self.assertRaises(MutationBlockedError):
            service.remove(REAL_TARGET)
        self.assertEqual(service.calls, 0)

    def test_synthetic_mode_executes_against_synthetic_targets(self):
        service = _ExampleService(mutation_policy=MutationPolicy.for_mode(ExecutionMode.LOCAL_SYNTHETIC))
        outcome = service.remove(SYNTHETIC_TARGET)
        self.assertTrue(outcome.executed)
        self.assertEqual(outcome.result, "removed")
        self.assertEqual(service.calls, 1)


class MutatingHttpClientTests(unittest.TestCase):
    def _client(self, mode, transport, hosts=(SYNTHETIC_OKTA_HOST,)):
        return MutatingHttpClient(
            mutation_policy=MutationPolicy.for_mode(mode),
            http_policy=HttpPolicy(),
            allowed_hosts=hosts,
            transport=transport,
        )

    def test_requires_mutation_policy(self):
        with self.assertRaises(TypeError):
            MutatingHttpClient(http_policy=HttpPolicy(), allowed_hosts=[SYNTHETIC_OKTA_HOST])  # type: ignore[call-arg]

    def test_read_only_mode_blocks_without_network(self):
        transport = FakeTransport()
        client = self._client(ExecutionMode.READ_ONLY_PRODUCTION, transport)
        with self.assertRaises(MutationBlockedError):
            client.send_mutation(REAL_TARGET, "DELETE", f"{SYNTHETIC_OKTA_URL}/api/v1/groups/SYNTH")
        self.assertEqual(transport.calls, [])

    def test_dry_run_plans_without_network(self):
        transport = FakeTransport()
        client = self._client(ExecutionMode.DRY_RUN_MUTATION, transport)
        outcome = client.send_mutation(REAL_TARGET, "DELETE", f"{SYNTHETIC_OKTA_URL}/api/v1/groups/SYNTH")
        self.assertFalse(outcome.executed)
        self.assertEqual(transport.calls, [])

    def test_synthetic_target_on_loopback_is_sent_once_without_retry(self):
        transport = FakeTransport(HttpResponse(503))
        client = self._client(ExecutionMode.LOCAL_SYNTHETIC, transport, hosts=("127.0.0.1",))
        outcome = client.send_mutation(SYNTHETIC_TARGET, "POST", "http://127.0.0.1:9/synthetic")
        self.assertTrue(outcome.executed)
        self.assertEqual(outcome.result.status, 503)
        self.assertEqual(len(transport.calls), 1)

    def test_rejects_safe_methods(self):
        client = self._client(ExecutionMode.DRY_RUN_MUTATION, FakeTransport())
        with self.assertRaises(ValueError):
            client.send_mutation(REAL_TARGET, "GET", f"{SYNTHETIC_OKTA_URL}/api/v1/groups")


class ReadOnlySurfaceTests(unittest.TestCase):
    def test_read_only_client_exposes_no_mutating_methods(self):
        for name in ("post", "put", "patch", "delete", "request", "send_mutation"):
            with self.subTest(name=name):
                self.assertFalse(hasattr(ReadOnlyHttpClient, name))

    def test_read_only_client_refuses_unsafe_methods_even_via_internals(self):
        transport = FakeTransport()
        client = ReadOnlyHttpClient(
            mode=ExecutionMode.READ_ONLY_PRODUCTION,
            http_policy=HttpPolicy(),
            allowed_hosts=[SYNTHETIC_OKTA_HOST],
            transport=transport,
        )
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            with self.subTest(method=method), self.assertRaises(MutationBlockedError):
                client._send_once(method, f"{SYNTHETIC_OKTA_URL}/x", None, None, 1)
        self.assertEqual(transport.calls, [])

    def test_read_only_http_module_does_not_import_mutation_code(self):
        imported = _imported_modules(REPO_ROOT / "app" / "core" / "http_client.py")
        self.assertNotIn("app.core.http_mutation", imported)
        self.assertNotIn("app.core.safety", imported)

    def test_only_approved_modules_import_mutating_http_client(self):
        importers = set()
        for path in (REPO_ROOT / "app").rglob("*.py"):
            if path.name == "http_mutation.py":
                continue
            if "app.core.http_mutation" in _imported_modules(path):
                importers.add(path.relative_to(REPO_ROOT).as_posix())
        self.assertEqual(importers - APPROVED_MUTATING_IMPORTERS, set())

    def test_mutating_import_allowlist_is_empty_in_current_prompt_package(self):
        # Owner decision D8 (docs/architecture/decisions.md): no executor is approved yet.
        self.assertEqual(APPROVED_MUTATING_IMPORTERS, frozenset())


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


if __name__ == "__main__":
    unittest.main()
