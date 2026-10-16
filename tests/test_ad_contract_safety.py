"""Static safety checks for the AD report contract (``app.integrations.ad``).

The Python side must not be able to reach a network, a process, or a mutation path. The
contract's golden fixtures must hold synthetic identities only.
"""

import ast
import json
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
AD_PACKAGE = REPO_ROOT / "app" / "integrations" / "ad"
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "ad"


class PythonBoundaryTests(unittest.TestCase):
    FORBIDDEN_IMPORTS = frozenset(
        {
            "subprocess", "socket", "ssl", "http", "http.client", "urllib", "urllib.request", "requests", "httpx",
            "ctypes", "app.core.safety",
        }
    )

    def test_ad_package_cannot_reach_a_network_a_process_or_a_mutation_path(self):
        for path in AD_PACKAGE.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module)
            with self.subTest(path=path.name):
                self.assertEqual(imported & self.FORBIDDEN_IMPORTS, set())

    def test_ad_package_does_no_file_io(self):
        for path in AD_PACKAGE.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name):
                self.assertNotRegex(text, r"\bopen\(|\.read_text\(|\.write_text\(|\bos\.")


class SyntheticFixtureTests(unittest.TestCase):
    SYNTHETIC_DOMAIN = re.compile(r"^(?:[a-z0-9-]+\.)*synthetic\.example$")
    SYNTHETIC_SID = re.compile(r"^S-1-5-21-(?P<d>[123])000000001-(?P=d)000000002-(?P=d)000000003(?:-\d+)?$")

    def _strings(self, value):
        if isinstance(value, dict):
            for item in value.values():
                yield from self._strings(item)
        elif isinstance(value, list):
            for item in value:
                yield from self._strings(item)
        elif isinstance(value, str):
            yield value

    def test_fixtures_contain_only_synthetic_identities(self):
        for path in FIXTURES.glob("*.json"):
            data = json.loads(path.read_text(encoding="utf-8"))
            for text in self._strings(data):
                with self.subTest(fixture=path.name, value=text[:60]):
                    if text.startswith("S-1-5-21-"):
                        self.assertRegex(text, self.SYNTHETIC_SID)
                    if "DC=" in text:
                        self.assertTrue(text.endswith("DC=synthetic,DC=example"), text)
                    if re.fullmatch(r"[a-z0-9.-]+\.[a-z]+", text) and "." in text:
                        self.assertRegex(text, self.SYNTHETIC_DOMAIN)
                    if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", text):
                        self.assertTrue(text.startswith("5e7e7000-0000-4000-8000-"), text)


if __name__ == "__main__":
    unittest.main()
