#Requires -Version 7
<#
.SYNOPSIS
    Runs the operator UI's browser tests against a synthetic, in-memory world. A required
    pre-pilot and pre-release gate wherever a supported browser is available.

.DESCRIPTION
    Starts a fresh synthetic OGWA world on 127.0.0.1 inside the test process (never the
    store under var/), launches a headless Chrome or Edge with a throw-away profile, and
    drives the operator workflows and the Null Meridian views over the DevTools protocol.
    The Demo Mode walk instead starts the demo runtime as an operator does
    (OGWA_RUNTIME_MODE=demo python -m app.api serve) over a demo store in a throw-away
    directory. Host-name resolution in that browser is limited to 127.0.0.1, so neither the
    page nor the browser can reach another system by name. Synthetic principals and data only.

    This suite is separate from scripts/check.ps1. It is a required gate before a pilot or a
    release whenever a supported browser is available (owner decision after P09). Results:

        exit 0  GATE PASSED   every browser test ran and passed
        exit 1  GATE FAILED   a test failed, errored, or was skipped
        exit 2  GATE NOT RUN  no supported browser was found; the gate is not satisfied

    -Browser picks the executable (default: Chrome, else Edge). -Screenshots writes PNGs of
    the synthetic pages to a directory of your choice; they are not test artefacts to commit.
#>
param(
    [string]$Browser,
    [string]$Screenshots
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

Push-Location $repo
$saved = Get-ChildItem Env: | Where-Object Name -like 'OGWA_*'
$code = 1
try {
    $saved | ForEach-Object { Remove-Item "Env:$($_.Name)" }
    $env:UI_BROWSER_TESTS = '1'
    if ($Browser) { $env:UI_BROWSER = $Browser }
    if ($Screenshots) { $env:UI_BROWSER_SCREENSHOTS = $Screenshots }

    $found = python -c "from tests.browser.harness import browser_path; print(browser_path() or '')"
    if ($LASTEXITCODE) { throw 'could not load the browser-test harness' }
    if (-not $found) {
        Write-Host 'GATE NOT RUN: no supported browser (Chrome or Edge) was found; set -Browser. The pre-pilot/release gate is not satisfied.'
        $code = 2
    }
    else {
        Write-Host "Browser: $found"
        python -m unittest tests.browser.test_operator_workflows tests.browser.test_null_meridian_views tests.browser.test_demo_null_meridian_ui tests.browser.test_genesee_press_ui tests.browser.test_hosted_demo_ui tests.browser.test_ui_ia tests.browser.test_candidate_tables tests.browser.test_remediation_drill_ui -v 2>&1 | Tee-Object -Variable lines
        $failed = $LASTEXITCODE
        $text = ($lines | Out-String)
        $skipped = [regex]::Matches($text, '\.\.\. skipped').Count
        if ($failed -or $skipped -or $text -notmatch '(?m)^OK\s*$') {
            Write-Host "GATE FAILED: exit $failed, $skipped skipped. Every browser test must run and pass."
            $code = 1
        }
        else {
            Write-Host 'GATE PASSED: every browser test ran and passed.'
            $code = 0
        }
    }
}
finally {
    Remove-Item Env:UI_BROWSER_TESTS, Env:UI_BROWSER, Env:UI_BROWSER_SCREENSHOTS -ErrorAction SilentlyContinue
    $saved | ForEach-Object { Set-Item "Env:$($_.Name)" $_.Value }
    Pop-Location
}
exit $code
