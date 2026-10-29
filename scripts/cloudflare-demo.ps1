#Requires -Version 7
<#
.SYNOPSIS
    Operator commands for the Cloudflare-hosted demo (docs/deployment/cloudflare-demo.md).

.DESCRIPTION
    Wraps wrangler around `python -m app.cloudflare`, which does all of OGWA's own work. Run
    from a machine logged in to the Cloudflare account (`npx wrangler login`); nothing here
    reads, prints, or stores a Cloudflare credential.

      -Build                       seed through the demo reset, validate, stage the Worker, plan D1
      -Bootstrap -ConfirmSyntheticBootstrap
                                   import the next due D1 phase (at most one per run; run each
                                   phase on a different UTC day: D1 Free allows 100,000 rows
                                   written a day)
      -Verify                      export the hosted D1 and validate it with the demo runtime's
                                   own checks (briefly makes D1 unavailable, so the Worker
                                   answers 503 while it runs)
      -Deploy                      deploy the staged Worker (pywrangler)

    The bootstrap is never reachable over HTTP: it is this script, run by an operator with
    wrangler access, and it refuses a D1 database that is not this build's import.
#>
param(
    [switch]$Build,
    [switch]$Bootstrap,
    [switch]$ConfirmSyntheticBootstrap,
    [switch]$Verify,
    [switch]$Deploy
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$worker = Join-Path $repo 'cloudflare/worker'
$buildDir = Join-Path $repo 'cloudflare/build'
$wrangler = 'wrangler@4.147.0'
$database = 'ogwa-demo-3'

function Invoke-Checked([string]$what, [scriptblock]$command) {
    & $command
    if ($LASTEXITCODE) { throw "$what failed (exit $LASTEXITCODE)" }
}

Push-Location $repo
try {
    if ($Build) {
        Invoke-Checked 'build' { python -m app.cloudflare build }
    }
    if ($Bootstrap) {
        if (-not $ConfirmSyntheticBootstrap) { throw 'Bootstrap needs -ConfirmSyntheticBootstrap' }
        $schema = Join-Path $buildDir 'd1-schema.json'
        $sql = python -m app.cloudflare sql schema
        Push-Location $worker
        try { npx --yes $wrangler d1 execute $database --remote --json --command $sql | Set-Content -Path $schema }
        finally { Pop-Location }
        if ($LASTEXITCODE) { throw 'could not read the D1 schema' }
        $next = python -m app.cloudflare next-phase --d1-schema $schema
        $code = $LASTEXITCODE
        Write-Host $next
        if ($code -eq 3) { Write-Host 'Nothing to import.' }
        elseif ($code -ne 0) { throw 'Refused: D1 is not this build''s import (see above)' }
        else {
            $file = Join-Path $buildDir ("d1/phase-{0}.sql" -f ([regex]::Match($next, 'phase (\d+)').Groups[1].Value))
            Push-Location $worker
            try { Invoke-Checked 'D1 import' { npx --yes $wrangler d1 execute $database --remote --file $file --yes } }
            finally { Pop-Location }
        }
    }
    if ($Verify) {
        $export = Join-Path $buildDir 'hosted-export.sql'
        Push-Location $worker
        try { Invoke-Checked 'D1 export' { npx --yes $wrangler d1 export $database --remote --output $export } }
        finally { Pop-Location }
        Invoke-Checked 'verify' { python -m app.cloudflare verify-export $export }
    }
    if ($Deploy) {
        Push-Location $worker
        try { Invoke-Checked 'deploy' { uvx --from workers-py pywrangler deploy } }
        finally { Pop-Location }
    }
}
finally {
    Pop-Location
}
