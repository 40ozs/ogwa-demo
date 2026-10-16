#Requires -Version 5.1
<#
.SYNOPSIS
    Tests for the OGWA.Remediation worker, against the in-memory synthetic adapter only.

.DESCRIPTION
    Dependency-free (no Pester). Runs on Windows PowerShell 5.1 and PowerShell 7.
    The JSON-boundary scenarios are compared with golden request/result pairs in
    tests/fixtures/remediation, which the Python tests also consume, so both sides of the
    contract test the same documents.

    Nothing here contacts Okta or a directory: the worker has no production adapter, and
    every test passes the synthetic adapter (or deliberately none). Every call that could
    reach ShouldProcess passes -WhatIf or -Confirm:$false, so nothing ever prompts.

.PARAMETER UpdateGolden
    Rewrite tests/fixtures/remediation/*.json from the current worker output. Review the diff.
#>
[CmdletBinding()]
param([switch]$UpdateGolden)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$fixtureDir = Join-Path $repo 'tests/fixtures/remediation'
$module = Import-Module (Join-Path $repo 'worker/OGWA.Remediation/OGWA.Remediation.psd1') -Force -PassThru

$observedAt = [datetime]::new(2026, 10, 5, 12, 0, 0, [DateTimeKind]::Utc)
$corp = 'corp.synthetic.example'
$corpDn = 'DC=corp,DC=synthetic,DC=example'
$quarantineOu = "OU=OGWA-Quarantine,$corpDn"
$domainSid = 'S-1-5-21-1000000001-1000000002-1000000003'
$script:passed = 0
$script:failures = New-Object System.Collections.Generic.List[string]

function Test-Case {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][scriptblock]$Body)
    try {
        & $Body
        $script:passed++
        Write-Host "ok    $Name"
    }
    catch {
        $script:failures.Add("$Name : $($_.Exception.Message)")
        Write-Host "FAIL  $Name : $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Assert-Equal {
    param($Expected, $Actual, [string]$Message = 'values differ')
    if (-not ($Expected -ceq $Actual)) { throw "$Message (expected <$Expected>, got <$Actual>)" }
}

function Assert-True {
    param([bool]$Condition, [string]$Message = 'condition is false')
    if (-not $Condition) { throw $Message }
}

function New-Group {
    param([int]$Rid, [string]$Name, [string]$Container = "OU=Groups,$corpDn", [hashtable]$Extra = @{})
    $group = @{
        ObjectGuid = '5e7e7000-0000-4000-8000-{0:d12}' -f (700000 + $Rid); Domain = $corp; Sid = "$domainSid-$Rid"
        DistinguishedName = "CN=$Name,$Container"; SamAccountName = $Name; AdminCount = $false
        ProtectedFromAccidentalDeletion = $false; IsCriticalSystemObject = $false; MemberCount = 0; MemberOfCount = 0
    }
    foreach ($key in $Extra.Keys) { $group[$key] = $Extra[$key] }
    $group
}

$groups = [ordered]@{
    retire      = New-Group 7001 'SYNTH-Legacy-Retire'
    adminCount  = New-Group 7002 'SYNTH-Tier0-Retire' -Extra @{ AdminCount = $true }
    pfad        = New-Group 7003 'SYNTH-Pfad' -Extra @{ ProtectedFromAccidentalDeletion = $true }
    unreadable  = New-Group 7004 'SYNTH-Pfad-Unreadable' -Extra @{ ProtectedFromAccidentalDeletion = $null }
    critical    = New-Group 7005 'SYNTH-Critical' -Extra @{ IsCriticalSystemObject = $true }
    wellKnown   = @{
        ObjectGuid = '5e7e7000-0000-4000-8000-000000700512'; Domain = $corp; Sid = "$domainSid-512"
        DistinguishedName = "CN=Domain Admins,CN=Users,$corpDn"; SamAccountName = 'Domain Admins'; AdminCount = $false
        ProtectedFromAccidentalDeletion = $false; IsCriticalSystemObject = $false; MemberCount = 0; MemberOfCount = 0
    }
    members     = New-Group 7007 'SYNTH-Has-Members' -Extra @{ MemberCount = 3 }
    unknown     = New-Group 7008 'SYNTH-Unknown-Members' -Extra @{ MemberCount = $null }
    nested      = New-Group 7009 'SYNTH-Nested-Child' -Extra @{ MemberOfCount = 1 }
    quarantined = New-Group 7010 'SYNTH-Already-Quarantined' -Container $quarantineOu
}

function New-TestAdapter {
    New-OgwaSyntheticRemediationAdapter -Groups @($groups.Values) -OrganizationalUnits @($quarantineOu) -OktaAssignments @(
        @{ AppId = '0oaSYNTHAPP01'; GroupId = '00gSYNTHGRP01'; GroupType = 'APP_GROUP' },
        @{ AppId = '0oaSYNTHAPP02'; GroupId = '00gSYNTHEVERYONE'; GroupType = 'BUILT_IN' })
}

function Get-Target {
    # Explicit-target parameters for one of the test groups, with optional overrides.
    param([Parameter(Mandatory)][string]$Key, [hashtable]$Override = @{})
    $group = $groups[$Key]
    $target = @{
        ObjectGuid = $group.ObjectGuid; Domain = $group.Domain; ExpectedSid = $group.Sid
        ExpectedDistinguishedName = $group.DistinguishedName
    }
    foreach ($name in $Override.Keys) { $target[$name] = $Override[$name] }
    $target
}

function Get-Changes {
    # The changes applied to the synthetic world, as an array even when there are none.
    param([Parameter(Mandatory)][hashtable]$Adapter)
    , @($Adapter.Log | Where-Object { $_ -like 'Change:*' })
}

function ConvertTo-CanonicalJson {
    param([Parameter(Mandatory)][string]$Json)
    ConvertTo-Json -InputObject (ConvertFrom-Json -InputObject $Json) -Depth 32 -Compress
}

function Write-Fixture {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Json)
    $path = Join-Path $fixtureDir $Name
    if ($UpdateGolden) {
        [void](New-Item -ItemType Directory -Force -Path $fixtureDir)
        [System.IO.File]::WriteAllText($path, ($Json -replace "`r`n", "`n") + "`n", (New-Object System.Text.UTF8Encoding $false))
    }
    Assert-True (Test-Path -LiteralPath $path) "missing golden file $path (run with -UpdateGolden)"
    Assert-Equal (ConvertTo-CanonicalJson ([System.IO.File]::ReadAllText($path))) (ConvertTo-CanonicalJson $Json) "output differs from $Name"
}

# --- the commands' shape -------------------------------------------------------------------

$stateChanging = @('Remove-OgwaADGroup', 'Move-OgwaADGroupToQuarantine', 'Remove-OgwaOktaGroupAssignment')

Test-Case 'every state-changing command supports ShouldProcess with ConfirmImpact High' {
    foreach ($name in $stateChanging) {
        $command = Get-Command -Name $name -Module $module.Name
        $binding = @($command.ScriptBlock.Attributes | Where-Object { $_ -is [System.Management.Automation.CmdletBindingAttribute] })[0]
        Assert-True $binding.SupportsShouldProcess "$name does not support ShouldProcess"
        Assert-Equal 'High' ([string]$binding.ConfirmImpact) "$name ConfirmImpact"
        Assert-True ($command.Parameters.ContainsKey('WhatIf') -and $command.Parameters.ContainsKey('Confirm')) "$name lacks -WhatIf/-Confirm"
    }
}

Test-Case 'no command takes a credential, a force switch, an override, or a script' {
    foreach ($command in @(Get-Command -Module $module.Name)) {
        foreach ($parameter in $command.Parameters.Values) {
            Assert-True ($parameter.Name -notmatch '^(Force|Override|Bypass|Credential|Script|Command|Filter|Execute|Apply)') (
                "$($command.Name) has parameter $($parameter.Name)")
            Assert-True ($parameter.ParameterType -ne [scriptblock] -and $parameter.ParameterType -ne [pscredential]) (
                "$($command.Name) -$($parameter.Name) accepts code or a credential")
        }
    }
}

Test-Case 'the module exports exactly its five commands' {
    Assert-Equal 'Invoke-OgwaRemediation,Move-OgwaADGroupToQuarantine,New-OgwaSyntheticRemediationAdapter,Remove-OgwaADGroup,Remove-OgwaOktaGroupAssignment' (
        (@($module.ExportedFunctions.Keys) | Sort-Object) -join ',')
}

# --- outcomes ------------------------------------------------------------------------------

Test-Case 'WhatIf describes the deletion and changes nothing' {
    $adapter = New-TestAdapter
    $target = Get-Target 'retire'
    $result = Remove-OgwaADGroup @target -Adapter $adapter -WhatIf -ObservedAt $observedAt
    Assert-Equal 'WhatIf' $result.outcome
    Assert-Equal $false $result.executed
    Assert-Equal $false $result.productionMutation
    Assert-Equal 'delete_group' $result.plannedChanges[0].action
    Assert-Equal 0 (Get-Changes $adapter).Count 'a change was applied under -WhatIf'
    Assert-Equal 10 $adapter.World.Groups.Count
}

Test-Case 'ValidateOnly checks everything and never consults ShouldProcess' {
    $adapter = New-TestAdapter
    $target = Get-Target 'retire'
    $result = Remove-OgwaADGroup @target -Adapter $adapter -ValidateOnly -Confirm:$false -ObservedAt $observedAt
    Assert-Equal 'ValidationOnly' $result.outcome
    Assert-Equal 0 (Get-Changes $adapter).Count
    Assert-Equal 'REQUEST_VALID,ADAPTER_SYNTHETIC,TARGET_SYNTHETIC,TARGET_RESOLVED,IDENTITY_MATCHES,NOT_PROTECTED,NO_MEMBERS,NO_PARENT_GROUPS' (
        (@($result.checks) | ForEach-Object { $_.code }) -join ',')
}

Test-Case 'an agreed confirmation changes only the synthetic in-memory world (Simulated)' {
    $adapter = New-TestAdapter
    $target = Get-Target 'retire'
    $result = Remove-OgwaADGroup @target -Adapter $adapter -Confirm:$false -ObservedAt $observedAt
    Assert-Equal 'Simulated' $result.outcome
    Assert-Equal $false $result.executed
    Assert-Equal $false $result.productionMutation
    Assert-Equal 'Change:RemoveGroup' ((Get-Changes $adapter) -join ',')
    Assert-Equal 9 $adapter.World.Groups.Count
    $again = Remove-OgwaADGroup @target -Adapter $adapter -Confirm:$false -ObservedAt $observedAt
    Assert-Equal 'TARGET_NOT_FOUND' ($again.blockedReasons -join ',')
}

Test-Case 'quarantine moves the group in the synthetic world only, and only when agreed' {
    $adapter = New-TestAdapter
    $target = Get-Target 'retire'
    $whatIf = Move-OgwaADGroupToQuarantine @target -QuarantineOu $quarantineOu -Adapter $adapter -WhatIf -ObservedAt $observedAt
    Assert-Equal 'WhatIf' $whatIf.outcome
    Assert-Equal "CN=SYNTH-Legacy-Retire,$quarantineOu" $whatIf.plannedChanges[0].details.'after.distinguishedName'
    Assert-Equal "CN=SYNTH-Legacy-Retire,OU=Groups,$corpDn" (@($adapter.World.Groups | Where-Object { $_.SamAccountName -eq 'SYNTH-Legacy-Retire' })[0].DistinguishedName)
    $moved = Move-OgwaADGroupToQuarantine @target -QuarantineOu $quarantineOu -Adapter $adapter -Confirm:$false -ObservedAt $observedAt
    Assert-Equal 'Simulated' $moved.outcome
    Assert-Equal "CN=SYNTH-Legacy-Retire,$quarantineOu" (@($adapter.World.Groups | Where-Object { $_.SamAccountName -eq 'SYNTH-Legacy-Retire' })[0].DistinguishedName)
}

Test-Case 'quarantine needs an existing OU in the same domain, and a group not already in it' {
    $adapter = New-TestAdapter
    $target = Get-Target 'retire'
    $missing = Move-OgwaADGroupToQuarantine @target -QuarantineOu "OU=Missing,$corpDn" -Adapter $adapter -Confirm:$false
    Assert-Equal 'QUARANTINE_OU_INVALID' ($missing.blockedReasons -join ',')
    $elsewhere = Move-OgwaADGroupToQuarantine @target -QuarantineOu 'OU=OGWA-Quarantine,DC=emea,DC=synthetic,DC=example' -Adapter $adapter -Confirm:$false
    Assert-Equal 'INVALID_REQUEST' ($elsewhere.blockedReasons -join ',')
    $already = Get-Target 'quarantined'
    $result = Move-OgwaADGroupToQuarantine @already -QuarantineOu $quarantineOu -Adapter $adapter -Confirm:$false
    Assert-Equal 'ALREADY_IN_QUARANTINE' ($result.blockedReasons -join ',')
    Assert-Equal 0 (Get-Changes $adapter).Count
}

Test-Case 'Okta unassignment: WhatIf, Simulated, missing assignment, built-in group' {
    $adapter = New-TestAdapter
    $whatIf = Remove-OgwaOktaGroupAssignment -OktaAppId '0oaSYNTHAPP01' -OktaGroupId '00gSYNTHGRP01' -Adapter $adapter -WhatIf
    Assert-Equal 'WhatIf' $whatIf.outcome
    Assert-Equal 2 $adapter.World.OktaAssignments.Count
    $builtIn = Remove-OgwaOktaGroupAssignment -OktaAppId '0oaSYNTHAPP02' -OktaGroupId '00gSYNTHEVERYONE' -Adapter $adapter -Confirm:$false
    Assert-Equal 'BUILT_IN_GROUP' ($builtIn.blockedReasons -join ',')
    $simulated = Remove-OgwaOktaGroupAssignment -OktaAppId '0oaSYNTHAPP01' -OktaGroupId '00gSYNTHGRP01' -Adapter $adapter -Confirm:$false
    Assert-Equal 'Simulated' $simulated.outcome
    Assert-Equal 1 $adapter.World.OktaAssignments.Count
    $missing = Remove-OgwaOktaGroupAssignment -OktaAppId '0oaSYNTHAPP01' -OktaGroupId '00gSYNTHGRP01' -Adapter $adapter -Confirm:$false
    Assert-Equal 'ASSIGNMENT_NOT_FOUND' ($missing.blockedReasons -join ',')
}

# --- there is no production adapter ----------------------------------------------------------

Test-Case 'without the synthetic adapter every command is Blocked, even when confirmed' {
    $adapter = New-TestAdapter
    $forged = @{ Kind = 'Synthetic'; Token = New-Object System.Object; World = $adapter.World; Log = $adapter.Log }
    $copied = [pscustomobject]$adapter
    foreach ($candidate in @($null, @{}, $forged, $copied, 'synthetic')) {
        $target = Get-Target 'retire'
        $delete = Remove-OgwaADGroup @target -Adapter $candidate -Confirm:$false
        Assert-Equal 'NO_PRODUCTION_ADAPTER' ($delete.blockedReasons -join ',')
        $target = Get-Target 'retire'
        $move = Move-OgwaADGroupToQuarantine @target -QuarantineOu $quarantineOu -Adapter $candidate -Confirm:$false
        Assert-Equal 'NO_PRODUCTION_ADAPTER' ($move.blockedReasons -join ',')
        $okta = Remove-OgwaOktaGroupAssignment -OktaAppId '0oaSYNTHAPP01' -OktaGroupId '00gSYNTHGRP01' -Adapter $candidate -Confirm:$false
        Assert-Equal 'NO_PRODUCTION_ADAPTER' ($okta.blockedReasons -join ',')
    }
    Assert-Equal 0 (Get-Changes $adapter).Count 'a forged adapter reached the synthetic world'
    Assert-Equal 10 $adapter.World.Groups.Count
}

Test-Case 'the synthetic adapter refuses to describe anything that is not synthetic' {
    $real = New-Group 7100 'Finance-Users'
    $real.Domain = 'corp.example.com'
    $real.DistinguishedName = 'CN=Finance-Users,OU=Groups,DC=corp,DC=example,DC=com'
    foreach ($attempt in @(
            { New-OgwaSyntheticRemediationAdapter -Groups @($real) },
            { New-OgwaSyntheticRemediationAdapter -OrganizationalUnits @('OU=Quarantine,DC=corp,DC=example,DC=com') },
            { New-OgwaSyntheticRemediationAdapter -OktaAssignments @(@{ AppId = '0oa1abcdEFGH'; GroupId = '00g1abcdEFGH'; GroupType = 'APP_GROUP' }) })) {
        $threw = $false
        try { [void](& $attempt) } catch { $threw = $true }
        Assert-True $threw 'a non-synthetic identity was accepted'
    }
}

Test-Case 'a non-synthetic target is Blocked even with the synthetic adapter' {
    $adapter = New-TestAdapter
    $target = Get-Target 'retire' @{ Domain = 'corp.example.com'; ExpectedDistinguishedName = 'CN=X,OU=Groups,DC=corp,DC=example,DC=com' }
    Assert-Equal 'NON_SYNTHETIC_TARGET' ((Remove-OgwaADGroup @target -Adapter $adapter -Confirm:$false).blockedReasons -join ',')
    $okta = Remove-OgwaOktaGroupAssignment -OktaAppId '0oa1abcdEFGH' -OktaGroupId '00g1abcdEFGH' -Adapter $adapter -Confirm:$false
    Assert-Equal 'NON_SYNTHETIC_TARGET' ($okta.blockedReasons -join ',')
}

# --- explicit targets ------------------------------------------------------------------------

Test-Case 'a pattern is never a target' {
    $adapter = New-TestAdapter
    foreach ($parameter in 'ObjectGuid', 'Domain', 'ExpectedSid', 'ExpectedDistinguishedName') {
        foreach ($value in '*', 'SYNTH-*', '?', '%', '[a-z]') {
            $target = Get-Target 'retire' @{ $parameter = $value }
            $result = Remove-OgwaADGroup @target -Adapter $adapter -Confirm:$false
            Assert-Equal 'WILDCARD_TARGET' ($result.blockedReasons -join ',') "$parameter=$value"
            Assert-Equal $null $result.target 'a pattern was echoed as a target'
        }
    }
    foreach ($pair in @(@('*', '00gSYNTHGRP01'), @('0oaSYNTHAPP01', '00g*'))) {
        $result = Remove-OgwaOktaGroupAssignment -OktaAppId $pair[0] -OktaGroupId $pair[1] -Adapter $adapter -Confirm:$false
        Assert-Equal 'WILDCARD_TARGET' ($result.blockedReasons -join ',')
    }
    Assert-Equal 0 (Get-Changes $adapter).Count
}

Test-Case 'malformed identifiers are refused before any lookup' {
    $adapter = New-TestAdapter
    $cases = @(
        @{ ObjectGuid = '' }, @{ ObjectGuid = '5E7E7000-0000-4000-8000-000000707001' }, @{ ObjectGuid = 'not-a-guid' },
        @{ Domain = 'CORP.SYNTHETIC.EXAMPLE' }, @{ ExpectedSid = 'S-1-x' }, @{ ExpectedSid = ' S-1-5-21-1' },
        @{ ExpectedDistinguishedName = 'CN=SYNTH-Legacy-Retire,OU=Groups,DC=emea,DC=synthetic,DC=example' })
    foreach ($override in $cases) {
        $target = Get-Target 'retire' $override
        $result = Remove-OgwaADGroup @target -Adapter $adapter -Confirm:$false
        Assert-Equal 'INVALID_REQUEST' ($result.blockedReasons -join ',') ($override.Keys -join ',')
    }
    Assert-Equal 0 @($adapter.Log).Count 'a malformed request reached the adapter'
}

Test-Case 'a changed identity blocks: the objectSid or DN differs from what OGWA approved' {
    $adapter = New-TestAdapter
    foreach ($override in @(@{ ExpectedSid = "$domainSid-9999" }, @{ ExpectedDistinguishedName = "CN=SYNTH-Renamed,OU=Groups,$corpDn" })) {
        $target = Get-Target 'retire' $override
        $result = Remove-OgwaADGroup @target -Adapter $adapter -Confirm:$false
        Assert-Equal 'TARGET_IDENTITY_CHANGED' ($result.blockedReasons -join ',')
    }
    $target = Get-Target 'retire' @{ ObjectGuid = '5e7e7000-0000-4000-8000-000000799999' }
    Assert-Equal 'TARGET_NOT_FOUND' ((Remove-OgwaADGroup @target -Adapter $adapter -Confirm:$false).blockedReasons -join ',')
    Assert-Equal 0 (Get-Changes $adapter).Count
}

# --- protection and dependencies -----------------------------------------------------------

Test-Case 'protected groups are Blocked whatever the caller agrees to' {
    $adapter = New-TestAdapter
    $expected = [ordered]@{ adminCount = 'PROTECTED_TARGET'; pfad = 'PROTECTED_TARGET'; critical = 'PROTECTED_TARGET'
        wellKnown = 'PROTECTED_TARGET'; unreadable = 'PROTECTION_UNDETERMINED' }
    foreach ($key in $expected.Keys) {
        $target = Get-Target $key
        $delete = Remove-OgwaADGroup @target -Adapter $adapter -Confirm:$false
        Assert-Equal $expected[$key] ($delete.blockedReasons -join ',') "delete $key"
        $target = Get-Target $key
        $move = Move-OgwaADGroupToQuarantine @target -QuarantineOu $quarantineOu -Adapter $adapter -Confirm:$false
        Assert-Equal $expected[$key] ($move.blockedReasons -join ',') "quarantine $key"
    }
    Assert-Equal 0 (Get-Changes $adapter).Count 'a protected group was changed'
}

Test-Case 'members and parent groups block, and so does an unknown member count' {
    $adapter = New-TestAdapter
    foreach ($case in @(@('members', 'HAS_MEMBERS'), @('unknown', 'HAS_MEMBERS'), @('nested', 'HAS_PARENT_GROUPS'))) {
        $target = Get-Target $case[0]
        Assert-Equal $case[1] ((Remove-OgwaADGroup @target -Adapter $adapter -Confirm:$false).blockedReasons -join ',') $case[0]
        $target = Get-Target $case[0]
        Assert-Equal $case[1] ((Move-OgwaADGroupToQuarantine @target -QuarantineOu $quarantineOu -Adapter $adapter -Confirm:$false).blockedReasons -join ',') $case[0]
    }
    Assert-Equal 0 (Get-Changes $adapter).Count
}

# --- the JSON boundary ---------------------------------------------------------------------------

function New-Request {
    # [IDictionary], not [hashtable]: casting to a hashtable would lose the target's key order.
    param([string]$Operation, [string]$Mode, [System.Collections.IDictionary]$Target,
        [string]$CorrelationId = 'req_5e7e70000000400080000000007000aa')
    [ordered]@{ schema = 'ogwa.remediation.request/v1'; operation = $Operation; mode = $Mode; correlationId = $CorrelationId
        target = $Target }
}

function Get-AdRequestTarget {
    param([string]$Key, [switch]$Quarantine, [hashtable]$Override = @{})
    $group = $groups[$Key]
    $target = [ordered]@{ objectGuid = $group.ObjectGuid; domain = $group.Domain; expectedSid = $group.Sid
        expectedDistinguishedName = $group.DistinguishedName }
    if ($Quarantine) { $target.quarantineOu = $quarantineOu }
    foreach ($name in $Override.Keys) { $target[$name] = $Override[$name] }
    $target
}

$boundary = [ordered]@{
    'whatif-ad-group-delete'          = @{ Request = New-Request 'AD_GROUP_DELETE' 'WhatIf' (Get-AdRequestTarget 'retire') }
    'whatif-ad-group-quarantine'      = @{ Request = New-Request 'AD_GROUP_QUARANTINE' 'WhatIf' (Get-AdRequestTarget 'retire' -Quarantine) }
    'whatif-okta-group-unassign'      = @{ Request = New-Request 'OKTA_GROUP_UNASSIGN' 'WhatIf' ([ordered]@{ oktaAppId = '0oaSYNTHAPP01'; oktaGroupId = '00gSYNTHGRP01' }) }
    'validation-only-ad-group-delete' = @{ Request = New-Request 'AD_GROUP_DELETE' 'ValidateOnly' (Get-AdRequestTarget 'retire') }
    'blocked-protected-group'         = @{ Request = New-Request 'AD_GROUP_DELETE' 'WhatIf' (Get-AdRequestTarget 'adminCount') }
    'blocked-identity-changed'        = @{ Request = New-Request 'AD_GROUP_DELETE' 'WhatIf' (Get-AdRequestTarget 'retire' -Override @{ expectedSid = "$domainSid-9999" }) }
    'blocked-no-production-adapter'   = @{ Request = New-Request 'AD_GROUP_DELETE' 'WhatIf' (Get-AdRequestTarget 'retire'); NoAdapter = $true }
    'blocked-execute-mode-refused'    = @{ Request = New-Request 'AD_GROUP_DELETE' 'Execute' (Get-AdRequestTarget 'retire') }
    'blocked-wildcard-target'         = @{ Request = New-Request 'AD_GROUP_DELETE' 'WhatIf' (Get-AdRequestTarget 'retire' -Override @{ objectGuid = '*' }) }
    'blocked-unknown-operation'       = @{ Request = New-Request 'RUN_SCRIPT' 'WhatIf' (Get-AdRequestTarget 'retire') }
}

foreach ($scenarioName in $boundary.Keys) {
    Test-Case "golden: $scenarioName" {
        $scenario = $boundary[$scenarioName]
        $adapter = New-TestAdapter
        $requestJson = ConvertTo-Json -InputObject $scenario.Request -Depth 8
        $parameters = @{ RequestJson = $requestJson; ObservedAt = $observedAt }
        if (-not $scenario.ContainsKey('NoAdapter')) { $parameters.Adapter = $adapter }
        $json = Invoke-OgwaRemediation @parameters
        Write-Fixture "$scenarioName.request.json" $requestJson
        Write-Fixture "$scenarioName.result.json" $json
        Assert-Equal 0 (Get-Changes $adapter).Count 'the JSON boundary changed the synthetic world'
    }
}

Test-Case 'golden: a Simulated result (direct call, never through the JSON boundary)' {
    $adapter = New-TestAdapter
    $target = Get-Target 'retire'
    $result = Remove-OgwaADGroup @target -Adapter $adapter -Confirm:$false -ObservedAt $observedAt -CorrelationId 'req_5e7e70000000400080000000007000bb'
    Write-Fixture 'simulated-ad-group-delete.result.json' (ConvertTo-Json -InputObject $result -Depth 16)
}

Test-Case 'golden outcomes match their names' {
    foreach ($scenarioName in $boundary.Keys) {
        $result = ConvertFrom-Json ([System.IO.File]::ReadAllText((Join-Path $fixtureDir "$scenarioName.result.json")))
        $expected = switch -Wildcard ($scenarioName) { 'whatif-*' { 'WhatIf' } 'validation-only-*' { 'ValidationOnly' } default { 'Blocked' } }
        Assert-Equal $expected $result.outcome $scenarioName
        Assert-Equal $false $result.executed $scenarioName
        Assert-Equal $false $result.productionMutation $scenarioName
    }
    $unknown = ConvertFrom-Json ([System.IO.File]::ReadAllText((Join-Path $fixtureDir 'blocked-unknown-operation.result.json')))
    Assert-Equal $null $unknown.operation 'an unknown operation is not echoed'
    Assert-Equal $null $unknown.correlationId 'an unreadable request has no correlation id'
}

Test-Case 'the boundary has no mode that changes anything' {
    $adapter = New-TestAdapter
    foreach ($mode in 'Execute', 'Simulate', 'Simulated', 'Apply', 'Confirm', 'whatif', '', 'PRODUCTION_MUTATION') {
        $json = Invoke-OgwaRemediation -RequestJson (ConvertTo-Json -InputObject (New-Request 'AD_GROUP_DELETE' $mode (Get-AdRequestTarget 'retire')) -Depth 8) -Adapter $adapter
        $result = ConvertFrom-Json $json
        Assert-Equal 'INVALID_REQUEST' ($result.blockedReasons -join ',') "mode $mode"
    }
    Assert-Equal 0 (Get-Changes $adapter).Count
    Assert-Equal 10 $adapter.World.Groups.Count
}

Test-Case 'the boundary refuses unknown keys, lists, extra target fields, and non-strings' {
    $adapter = New-TestAdapter
    $base = New-Request 'AD_GROUP_DELETE' 'WhatIf' (Get-AdRequestTarget 'retire')
    $withScript = New-Request 'AD_GROUP_DELETE' 'WhatIf' (Get-AdRequestTarget 'retire')
    $withScript.script = 'Remove-Item C:\'
    $withTemplate = New-Request 'AD_GROUP_DELETE' 'WhatIf' (Get-AdRequestTarget 'retire')
    $withTemplate.jobTemplateId = 42
    $extraTarget = New-Request 'AD_GROUP_DELETE' 'WhatIf' (Get-AdRequestTarget 'retire' -Override @{ force = 'true' })
    $listTarget = New-Request 'AD_GROUP_DELETE' 'WhatIf' $null
    $listTarget.target = @((Get-AdRequestTarget 'retire'), (Get-AdRequestTarget 'nested'))
    $numberTarget = New-Request 'OKTA_GROUP_UNASSIGN' 'WhatIf' ([ordered]@{ oktaAppId = 1; oktaGroupId = '00gSYNTHGRP01' })
    $badSchema = New-Request 'AD_GROUP_DELETE' 'WhatIf' (Get-AdRequestTarget 'retire')
    $badSchema.schema = 'ogwa.remediation.request/v2'
    $documents = @(
        (ConvertTo-Json -InputObject $withScript -Depth 8), (ConvertTo-Json -InputObject $withTemplate -Depth 8),
        (ConvertTo-Json -InputObject $extraTarget -Depth 8), (ConvertTo-Json -InputObject $listTarget -Depth 8),
        (ConvertTo-Json -InputObject $numberTarget -Depth 8), (ConvertTo-Json -InputObject $badSchema -Depth 8),
        '[]', '"text"', '{', '', (ConvertTo-Json -InputObject @($base, $base) -Depth 8))
    foreach ($document in $documents) {
        $result = ConvertFrom-Json (Invoke-OgwaRemediation -RequestJson $document -Adapter $adapter)
        Assert-Equal 'Blocked' $result.outcome $document
        Assert-Equal 'INVALID_REQUEST' ($result.blockedReasons -join ',') $document
    }
    Assert-Equal 0 @($adapter.Log).Count 'an invalid request reached the adapter'
}

Test-Case 'every boundary result states executed false and productionMutation false' {
    $adapter = New-TestAdapter
    foreach ($key in $groups.Keys) {
        foreach ($mode in 'WhatIf', 'ValidateOnly') {
            $json = Invoke-OgwaRemediation -RequestJson (ConvertTo-Json -InputObject (New-Request 'AD_GROUP_DELETE' $mode (Get-AdRequestTarget $key)) -Depth 8) -Adapter $adapter
            Assert-True ($json -match '"executed":\s*false') "$key $mode"
            Assert-True ($json -match '"productionMutation":\s*false') "$key $mode"
            Assert-True ($json -notmatch '"outcome":\s*"Simulated"') "$key $mode reached Simulated through the boundary"
        }
    }
    Assert-Equal 0 (Get-Changes $adapter).Count
}

Write-Host ''
Write-Host "$script:passed passed, $($script:failures.Count) failed (PowerShell $($PSVersionTable.PSVersion))"
if ($script:failures.Count -gt 0) {
    $script:failures | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    exit 1
}
exit 0
