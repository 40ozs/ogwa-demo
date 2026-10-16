import ast
import unittest
from pathlib import Path

from app.core.errors import MutationBlockedError
from app.core.modes import ExecutionMode
from app.core.safety import (
    MutationCapableService,
    MutationDecision,
    MutationPolicy,
    MutationRequest,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
# Standard-library and common third-party modules that open outbound connections or start processes.
OUTBOUND_MODULES = ("socket", "ssl", "urllib.request", "urllib.error", "http.client", "http.server", "ftplib", "smtplib",
                    "asyncio", "subprocess", "requests", "httpx", "aiohttp")
# The one reviewed server import: the demo's WSGI server, bound to loopback or a container interface.
APPROVED_SERVER_IMPORTERS = {"app/api/local.py": "wsgiref.simple_server"}

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


class NoOutboundClientTests(unittest.TestCase):
    """This build has no Okta, AD, or AAP client and no outbound HTTP client; nothing may add one unreviewed."""

    def test_no_application_module_imports_an_outbound_network_or_process_module(self):
        for path in sorted((REPO_ROOT / "app").rglob("*.py")):
            relative = path.relative_to(REPO_ROOT).as_posix()
            for name in _imported_modules(path):
                with self.subTest(module=relative, imports=name):
                    self.assertFalse(any(name == f or name.startswith(f + ".") for f in OUTBOUND_MODULES))
                    if name.startswith("wsgiref"):
                        self.assertEqual(APPROVED_SERVER_IMPORTERS.get(relative), name)


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
