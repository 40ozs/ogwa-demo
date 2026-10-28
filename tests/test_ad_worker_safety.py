"""Static safety checks for the AD boundary (P05).

The PowerShell worker must be read-only by construction: it may call only the listed
Get-* AD cmdlets, every search must be bounded, and it writes no files. The Python side
must not be able to reach a network or a mutation path. Test fixtures must be synthetic.
"""

import ast
import json
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKER = REPO_ROOT / "worker" / "OGWA.ADReader"
PS_TESTS = REPO_ROOT / "tests" / "powershell"
AD_PACKAGE = REPO_ROOT / "app" / "integrations" / "ad"
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "ad"

ALLOWED_AD_CMDLETS = frozenset({"Get-ADForest", "Get-ADDomain", "Get-ADDomainController", "Get-ADGroup", "Get-ADObject"})
AD_CMDLET = re.compile(r"\b[A-Za-z]+-AD[A-Za-z]+\b")
# Commands that change state or run arbitrary code. None may appear in the worker.
FORBIDDEN_IN_WORKER = re.compile(
    r"\b(?:Invoke-Expression|iex|Start-Process|Start-Job|Invoke-Command|New-PSSession|Enter-PSSession|Invoke-WebRequest|"
    r"Invoke-RestMethod|Set-Content|Add-Content|Out-File|Export-Csv|New-Item|Remove-Item|Move-Item|Copy-Item|"
    r"Rename-Item|Set-Item|Clear-Content|Set-Acl|Add-Type|Register-ObjectEvent)\b"
    r"|\[adsi\]|DirectoryEntry|CommitChanges|SetInfo|\.Put\(|DirectoryServices\.Protocols|WriteAll"
    r"|System\.Net|WebClient|HttpClient|ScriptBlock\]::Create|NewScriptBlock",
    re.IGNORECASE,
)


def _sources(root: Path, *patterns: str):
    for pattern in patterns:
        yield from sorted(root.rglob(pattern))


class WorkerReadOnlyTests(unittest.TestCase):
    def test_worker_uses_only_read_only_ad_cmdlets(self):
        found = {}
        for path in _sources(WORKER, "*.ps1", "*.psm1", "*.psd1"):
            for match in AD_CMDLET.findall(path.read_text(encoding="utf-8")):
                found.setdefault(match, set()).add(path.name)
        self.assertEqual(set(found) - ALLOWED_AD_CMDLETS, set(), found)
        self.assertTrue({"Get-ADObject", "Get-ADGroup"} <= set(found))

    def test_powershell_tests_and_fakes_use_no_ad_cmdlets_that_change_state(self):
        for path in _sources(PS_TESTS, "*.ps1", "*.psm1"):
            with self.subTest(path=path.name):
                self.assertEqual(set(AD_CMDLET.findall(path.read_text(encoding="utf-8"))) - ALLOWED_AD_CMDLETS, set())

    def test_worker_runs_no_arbitrary_code_and_writes_nothing(self):
        for path in _sources(WORKER, "*.ps1", "*.psm1", "*.psd1"):
            with self.subTest(path=path.name):
                self.assertEqual(FORBIDDEN_IN_WORKER.findall(path.read_text(encoding="utf-8")), [])

    def test_the_forbidden_pattern_catches_dynamic_code_and_network_apis(self):
        for sample in ("[ScriptBlock]::Create($text)", "$ExecutionContext.InvokeCommand.NewScriptBlock($text)",
                       "Start-Job { 1 }", "[System.Net.Sockets.TcpClient]::new()", "New-Object Net.WebClient",
                       "[Net.Http.HttpClient]::new()"):
            with self.subTest(sample=sample):
                self.assertTrue(FORBIDDEN_IN_WORKER.search(sample))
        for allowed in ("Import-Module ActiveDirectory", "& $command @arguments"):  # the worker relies on both
            with self.subTest(allowed=allowed):
                self.assertIsNone(FORBIDDEN_IN_WORKER.search(allowed))

    def test_every_directory_search_is_bounded_and_scoped(self):
        searches = 0
        for path in _sources(WORKER, "*.ps1"):
            for line in path.read_text(encoding="utf-8").splitlines():
                if re.search(r"\bGet-ADObject\s+-", line):
                    searches += 1
                    with self.subTest(line=line.strip()[:80]):
                        self.assertIn("-ResultSetSize", line)
                        self.assertIn("-SearchBase", line)
                        self.assertIn("-Server", line)
                        self.assertIn("-LDAPFilter", line)
        self.assertEqual(searches, 4)

    def test_worker_accepts_no_credential_parameter(self):
        for path in _sources(WORKER, "*.ps1"):
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name):
                self.assertNotRegex(text, r"(?i)\[(?:PSCredential|SecureString)\]|-Credential\b|ConvertTo-SecureString")

    def test_manifest_exports_only_the_reader_functions(self):
        manifest = (WORKER / "OGWA.ADReader.psd1").read_text(encoding="utf-8")
        exported = re.search(r"FunctionsToExport\s*=\s*@\(([^)]*)\)", manifest).group(1)
        self.assertEqual(
            sorted(re.findall(r"'([^']+)'", exported)),
            ["Get-OgwaADGroupReport", "Invoke-OgwaADReader", "New-OgwaADDirectory"],
        )

    def test_check_script_runs_the_powershell_worker_tests(self):
        check = (REPO_ROOT / "scripts" / "check.ps1").read_text(encoding="utf-8")
        self.assertIn("tests/powershell/Test-OgwaADReader.ps1", check)


class PythonBoundaryTests(unittest.TestCase):
    FORBIDDEN_IMPORTS = frozenset(
        {
            "subprocess", "socket", "ssl", "http", "http.client", "urllib", "urllib.request", "requests", "httpx",
            "ctypes", "app.core.http_client", "app.core.http_mutation", "app.core.safety",
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
