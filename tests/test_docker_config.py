"""The Docker runtime's configuration: demo only, no secrets, non-root, loopback, health-checked.

The image and the running container are checked end to end by ``scripts/docker_smoke.py``
(it needs Docker); these checks need nothing but the files.
"""

import importlib.util
import re
import unittest
from pathlib import Path
from unittest import mock

from app.api.__main__ import DEFAULT_PORT
from app.core.config import FORBIDDEN_FOREIGN_CREDENTIALS, LIVE_INTEGRATION_KEYS

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
COMPOSE = (REPO_ROOT / "compose.yaml").read_text(encoding="utf-8")
DOCKERIGNORE = (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8")
SMOKE = REPO_ROOT / "scripts" / "docker_smoke.py"


def instructions(name: str) -> list[str]:
    return re.findall(rf"^{name}\s+(.+?)$", DOCKERFILE, re.M)


class DockerfileTests(unittest.TestCase):
    def test_the_base_image_is_a_pinned_python_slim_release(self):
        self.assertEqual(len(instructions("FROM")), 1)
        self.assertRegex(instructions("FROM")[0], r"^python:3\.1[1-9]-slim-[a-z]+$")

    def test_the_image_holds_the_application_and_its_configuration_only(self):
        self.assertEqual(instructions("COPY"), ["app/ app/", "config/ config/"])
        self.assertEqual([line.strip() for line in DOCKERIGNORE.splitlines() if line.strip() and not line.startswith("#")],
                         ["*", "!app/", "!config/", "**/__pycache__", "**/*.py[cod]"])

    def test_it_runs_as_a_non_root_user(self):
        self.assertEqual(instructions("USER"), ["ogwa"])
        self.assertIn("useradd --system", DOCKERFILE)

    def test_it_bakes_in_no_configuration_and_no_secret(self):
        environment = " ".join(instructions("ENV") + instructions("ARG"))
        self.assertNotIn("OGWA_", environment)
        for key in (*LIVE_INTEGRATION_KEYS, *FORBIDDEN_FOREIGN_CREDENTIALS, "TOKEN", "SECRET", "PASSWORD"):
            self.assertNotIn(key, DOCKERFILE)

    def test_it_seeds_on_first_start_then_serves_the_demo_on_all_container_interfaces(self):
        command = instructions("CMD")[0]
        self.assertIn("python -m app.runtime reset-demo --confirm-synthetic-reset", command)
        self.assertIn("exec python -m app.api serve --host 0.0.0.0", command)
        self.assertEqual(instructions("EXPOSE"), [str(DEFAULT_PORT)])

    def test_health_is_the_api_health_endpoint_with_live_integrations_off(self):
        healthcheck = DOCKERFILE[DOCKERFILE.index("HEALTHCHECK"):]
        self.assertIn(f"http://127.0.0.1:{DEFAULT_PORT}/api/v1/health", healthcheck)
        self.assertIn("b['liveIntegrations'] is not False", healthcheck)


class ComposeTests(unittest.TestCase):
    def test_the_port_is_published_to_the_host_loopback_only(self):
        self.assertEqual(re.findall(r'^\s+- "([^"]+)"$', COMPOSE, re.M)[0], f"127.0.0.1:{DEFAULT_PORT}:{DEFAULT_PORT}")

    def test_the_demo_store_is_a_named_volume_and_nothing_else_is_configured(self):
        self.assertIn("- demo-store:/app/var", COMPOSE)
        self.assertIn("init: true", COMPOSE)
        self.assertNotIn("environment", COMPOSE)
        self.assertNotIn("env_file", COMPOSE)
        self.assertNotIn("OGWA_", COMPOSE)


class DockerSmokeTests(unittest.TestCase):
    def test_the_smoke_runs_in_its_own_compose_project_never_the_reviewers(self):
        # It runs `down -v`: in the default project that would delete the reviewer's demo store volume.
        spec = importlib.util.spec_from_file_location("docker_smoke", SMOKE)
        smoke = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(smoke)
        calls = []
        with mock.patch.object(smoke.subprocess, "run", side_effect=lambda argv, **kw: calls.append(argv)):
            smoke.compose("down", "-v")
        self.assertEqual(calls, [["docker", "compose", "-p", "ogwa-docker-smoke", "down", "-v"]])
        self.assertEqual(re.findall(r'"compose"', SMOKE.read_text(encoding="utf-8")), ['"compose"'],
                         "nothing reaches Compose except through compose()")


if __name__ == "__main__":
    unittest.main()
