import re
import unittest
from pathlib import Path

from app.core.config import KNOWN_KEYS, LIVE_INTEGRATION_KEYS, load_settings

REPO_ROOT = Path(__file__).resolve().parents[1]

TEXT_SUFFIXES = {".py", ".md", ".toml", ".ps1", ".psm1", ".psd1", ".txt", ".json", ".yml", ".yaml", ".example", ".gitignore",
                 ".js", ".mjs", ".css", ".html", ".svg"}  # the last five: the operator UI
SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "var", "data", "evidence", "exports"}

# Credential-shaped strings. Matches containing "synthetic" are deliberate test values.
CREDENTIAL_PATTERNS = (
    re.compile(r"\bSSWS\s+[A-Za-z0-9_\-]{20,}"),
    re.compile(r"\bBearer\s+[A-Za-z0-9_\-.=]{30,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b00[A-Za-z0-9_\-]{40}\b"),  # Okta API token shape
)


def _repo_text_files():
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.relative_to(REPO_ROOT).parts):
            continue
        if path.suffix in TEXT_SUFFIXES or path.name in {".gitignore", ".env.example"}:
            yield path


def _env_example_entries() -> dict[str, str]:
    entries = {}
    for line in (REPO_ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            key, _, value = line.partition("=")
            entries[key.strip()] = value.strip()
    return entries


class RepositoryHygieneTests(unittest.TestCase):
    def test_env_example_lists_exactly_the_known_keys(self):
        self.assertEqual(set(_env_example_entries()), set(KNOWN_KEYS))

    def test_env_example_names_no_live_setting_and_loads_as_the_demo(self):
        entries = _env_example_entries()
        self.assertFalse(set(entries) & set(LIVE_INTEGRATION_KEYS))
        settings = load_settings(entries)
        self.assertEqual((settings.runtime_mode.value, settings.mode.value), ("demo", "LOCAL_SYNTHETIC"))

    def test_gitignore_excludes_sensitive_material(self):
        lines = set((REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines())
        for required in (".env", "!.env.example", "*token-cache*", "*.sqlite", "*.db", "var/", "evidence/", "*.csv", "*.log"):
            with self.subTest(required=required):
                self.assertIn(required, lines)

    def test_no_credential_shaped_strings_in_repository(self):
        findings = []
        for path in _repo_text_files():
            text = path.read_text(encoding="utf-8", errors="replace")
            for pattern in CREDENTIAL_PATTERNS:
                for match in pattern.finditer(text):
                    if "synthetic" not in match.group(0).lower():
                        findings.append(f"{path.relative_to(REPO_ROOT)}: {pattern.pattern}")
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
