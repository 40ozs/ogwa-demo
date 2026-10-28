"""Static safety checks for the remediation worker (P10), worker/OGWA.Remediation.

The worker must be unable to change anything outside its own in-memory synthetic adapter:
no AD or Okta cmdlets or HTTP calls at all, no dynamic code, no file writes, no credential;
every state-changing command declares SupportsShouldProcess with ConfirmImpact High and
reaches the synthetic change only after ShouldProcess; and the JSON boundary always passes
-WhatIf and never -Confirm:$false.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKER = REPO_ROOT / "worker" / "OGWA.Remediation"
STATE_CHANGING = ("Remove-OgwaADGroup", "Move-OgwaADGroupToQuarantine", "Remove-OgwaOktaGroupAssignment")

AD_OR_OKTA_CMDLET = re.compile(r"\b[A-Za-z]+-(?:AD|Okta)[A-Za-z]+\b")
FORBIDDEN = re.compile(
    r"\b(?:Invoke-Expression|iex|Add-Type|Start-Process|Start-Job|Invoke-Command|New-PSSession|Enter-PSSession|"
    r"Invoke-WebRequest|Invoke-RestMethod|Import-Module|Set-Content|Add-Content|Out-File|Export-Csv|New-Item|"
    r"Remove-Item|Move-Item|Copy-Item|Rename-Item|Set-Item|Clear-Content|Set-Acl|Register-ObjectEvent)\b"
    r"|\[adsi\]|DirectoryEntry|DirectoryServices|CommitChanges|SetInfo|\.Put\(|System\.Net|WebClient|HttpClient"
    r"|ScriptBlock\]::Create|NewScriptBlock|WriteAll",
    re.IGNORECASE,
)
# Running code held in a variable: the call operator on a variable, or dot-sourcing one.
DYNAMIC_INVOCATION = re.compile(r"(?m)&\s*\$|^\s*\.\s+\$")


def _sources():
    return sorted(p for p in WORKER.rglob("*") if p.suffix in (".ps1", ".psm1", ".psd1"))


def _function_file(name: str) -> str:
    return (WORKER / "Public" / f"{name}.ps1").read_text(encoding="utf-8")


class RemediationWorkerStaticTests(unittest.TestCase):
    def test_the_worker_names_no_ad_or_okta_cmdlet_and_no_http_or_directory_api(self):
        for path in _sources():
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name):
                # The worker's own command names contain "OgwaAD", never "-AD"/"-Okta" directly.
                self.assertEqual(AD_OR_OKTA_CMDLET.findall(text), [])
                self.assertEqual(FORBIDDEN.findall(text), [])

    def test_no_dynamic_code_outside_the_module_loader(self):
        for path in _sources():
            if path.suffix == ".psm1":
                continue  # the loader dot-sources the module's own Private/Public files
            with self.subTest(path=path.name):
                self.assertEqual(DYNAMIC_INVOCATION.findall(path.read_text(encoding="utf-8")), [])
        loader = (WORKER / "OGWA.Remediation.psm1").read_text(encoding="utf-8")
        self.assertEqual(len(DYNAMIC_INVOCATION.findall(loader)), 1)
        self.assertIn("Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot $folder)", loader)

    def test_no_credential_is_accepted(self):
        for path in _sources():
            with self.subTest(path=path.name):
                self.assertNotRegex(path.read_text(encoding="utf-8"),
                                    r"(?i)\[(?:PSCredential|SecureString)\]|-Credential\b|ConvertTo-SecureString")

    def test_state_changing_commands_ask_shouldprocess_before_any_change(self):
        for name in STATE_CHANGING:
            text = _function_file(name)
            with self.subTest(command=name):
                self.assertIn("[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]", text)
                self.assertEqual(text.count("$PSCmdlet.ShouldProcess("), 1)
                gate = text.index("$PSCmdlet.ShouldProcess(")
                self.assertEqual(text.count("Invoke-OgwaSyntheticChange"), 1)
                self.assertGreater(text.index("Invoke-OgwaSyntheticChange"), gate)
                self.assertLess(text.index("if ($ValidateOnly)"), gate)
                self.assertIn("if ($WhatIfPreference)", text[gate:])
                self.assertNotRegex(text, r"(?i)\$(?:WhatIfPreference|ConfirmPreference)\s*=")
                self.assertNotRegex(text, r"(?i)executed\s*=\s*\$true|productionMutation\s*=\s*\$true")

    def test_the_synthetic_change_is_defined_once_and_refuses_foreign_adapters(self):
        users = [p.name for p in _sources() if "Invoke-OgwaSyntheticChange" in p.read_text(encoding="utf-8")]
        self.assertEqual(sorted(users), sorted(["Synthetic.ps1", *(f"{n}.ps1" for n in STATE_CHANGING)]))
        synthetic = (WORKER / "Private" / "Synthetic.ps1").read_text(encoding="utf-8")
        body = synthetic[synthetic.index("function Invoke-OgwaSyntheticChange"):]
        self.assertLess(body.index("Test-OgwaSyntheticAdapter"), body.index("switch ($Change)"))
        self.assertIn("[object]::ReferenceEquals($Adapter['Token'], $script:SyntheticAdapterToken)", synthetic)

    def test_the_json_boundary_always_passes_whatif_and_never_skips_confirmation(self):
        text = _function_file("Invoke-OgwaRemediation")
        self.assertIn("WhatIf = $true", text)
        self.assertNotRegex(text, r"(?i)Confirm\s*[:=]\s*\$false|WhatIf\s*[:=]\s*\$false")
        self.assertNotIn("Invoke-OgwaSyntheticChange", text)
        contract = (WORKER / "contract.json").read_text(encoding="utf-8")
        self.assertIn('"modes": ["WhatIf", "ValidateOnly"]', contract)

    def test_results_state_executed_and_production_mutation_false_literally(self):
        common = (WORKER / "Private" / "Common.ps1").read_text(encoding="utf-8")
        self.assertEqual(len(re.findall(r"executed\s*=\s*\$false", common)), 2)
        self.assertEqual(len(re.findall(r"productionMutation\s*=\s*\$false", common)), 2)
        for path in _sources():
            with self.subTest(path=path.name):
                self.assertNotRegex(path.read_text(encoding="utf-8"), r"\.(?:executed|productionMutation)\s*=")

    def test_the_manifest_exports_exactly_the_five_commands(self):
        manifest = (WORKER / "OGWA.Remediation.psd1").read_text(encoding="utf-8")
        exported = re.search(r"FunctionsToExport\s*=\s*@\(([^)]*)\)", manifest).group(1)
        self.assertEqual(sorted(re.findall(r"'([^']+)'", exported)),
                         ["Invoke-OgwaRemediation", "Move-OgwaADGroupToQuarantine", "New-OgwaSyntheticRemediationAdapter",
                          "Remove-OgwaADGroup", "Remove-OgwaOktaGroupAssignment"])
        self.assertIn("RequiredModules   = @()", manifest)

    def test_the_standard_check_runs_the_worker_tests_on_both_runtimes(self):
        check = (REPO_ROOT / "scripts" / "check.ps1").read_text(encoding="utf-8")
        self.assertIn("tests/powershell/Test-OgwaRemediation.ps1", check)
        self.assertIn("powershell.exe -NoProfile -NonInteractive -File $suite", check)

    def test_the_worker_tests_never_let_shouldprocess_prompt(self):
        tests = (REPO_ROOT / "tests" / "powershell" / "Test-OgwaRemediation.ps1").read_text(encoding="utf-8")
        calls = re.findall(r"(?m)(?:Remove-OgwaADGroup|Move-OgwaADGroupToQuarantine|Remove-OgwaOktaGroupAssignment)"
                           r" @?[^\n]*", tests)
        self.assertGreater(len(calls), 10)
        for call in calls:
            if call.startswith(("Remove-OgwaADGroup @common", "Move-OgwaADGroupToQuarantine @common",
                                "Remove-OgwaOktaGroupAssignment @common")):
                continue
            with self.subTest(call=call[:80]):
                self.assertRegex(call, r"-WhatIf|-Confirm:\$false|-ValidateOnly")


if __name__ == "__main__":
    unittest.main()
