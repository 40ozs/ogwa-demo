#Requires -Version 7
<#
.SYNOPSIS
    Runs OGWA's project-local static checks and unit tests.

.DESCRIPTION
    Byte-compiles the sources, runs the unittest suite, and runs the PowerShell tests of the
    dry-run remediation worker. Contacts no external systems; the only network use is a
    throwaway HTTP server bound to 127.0.0.1, and the worker tests use a synthetic in-memory
    adapter.
    OGWA_* variables in the caller's environment are cleared for the run so local
    configuration cannot influence results.
#>
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

Push-Location $repo
$saved = Get-ChildItem Env: | Where-Object Name -like 'OGWA_*'
try {
    $saved | ForEach-Object { Remove-Item "Env:$($_.Name)" }

    # The UI's JavaScript unit tests run under Node's built-in runner (no packages, no
    # network); they are part of the standard check.
    if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
        throw 'Node.js is required for the UI logic tests (tests/ui); install an approved Node.js and retry'
    }

    python -m compileall -q app tests
    if ($LASTEXITCODE) { throw 'compileall failed' }

    python -m unittest discover -s tests -t . -v
    if ($LASTEXITCODE) { throw 'unit tests failed' }

    # The remediation worker (dry-run only) against its in-memory synthetic adapter. Also on
    # Windows PowerShell 5.1 when present.
    foreach ($suite in @('tests/powershell/Test-OgwaRemediation.ps1')) {
        pwsh -NoProfile -NonInteractive -File $suite
        if ($LASTEXITCODE) { throw "PowerShell worker tests failed (pwsh): $suite" }
        if (Get-Command powershell.exe -ErrorAction SilentlyContinue) {
            powershell.exe -NoProfile -NonInteractive -File $suite
            if ($LASTEXITCODE) { throw "PowerShell worker tests failed (Windows PowerShell 5.1): $suite" }
        }
    }
}
finally {
    $saved | ForEach-Object { Set-Item "Env:$($_.Name)" $_.Value }
    Pop-Location
}
