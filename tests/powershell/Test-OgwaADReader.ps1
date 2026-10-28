#Requires -Version 5.1
<#
.SYNOPSIS
    Tests for the OGWA.ADReader worker, against a synthetic directory only.

.DESCRIPTION
    Dependency-free (no Pester). Runs on Windows PowerShell 5.1 and PowerShell 7.
    The scenario reports are compared with the golden files in tests/fixtures/ad, which
    the Python tests also consume, so both sides of the contract test the same documents.

    Nothing here contacts a directory: every test passes a synthetic -Directory, and the
    one test of the default accessor runs only on hosts without the ActiveDirectory module.

.PARAMETER UpdateGolden
    Rewrite tests/fixtures/ad/*.json from the current worker output. Review the diff.
#>
[CmdletBinding()]
param([switch]$UpdateGolden)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$fixtureDir = Join-Path $repo 'tests/fixtures/ad'
$reader = Import-Module (Join-Path $repo 'worker/OGWA.ADReader/OGWA.ADReader.psd1') -Force -PassThru
Import-Module (Join-Path $PSScriptRoot 'FakeADDirectory.psm1') -Force

$observedAt = [datetime]::new(2026, 10, 4, 12, 0, 0, [DateTimeKind]::Utc)
$corp = 'corp.synthetic.example'
$emea = 'emea.corp.synthetic.example'
$apac = 'apac.corp.synthetic.example'
$script:passed = 0
$script:failures = [System.Collections.Generic.List[string]]::new()

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

function New-Request {
    param([string]$By, [string]$Value, [string]$Domain, [hashtable]$Include, [hashtable]$Limits)
    $request = [ordered]@{
        schema = 'ogwa.ad.group-read-request/v1'
        lookup = [ordered]@{ by = $By; value = $Value; domain = if ($Domain) { $Domain } else { $null } }
    }
    if ($Include) { $request.include = $Include }
    if ($Limits) { $request.limits = $Limits }
    $request
}

function Get-Report {
    # Runs the worker through its JSON boundary and returns the parsed report.
    param([Parameter(Mandatory)]$Request, [Parameter(Mandatory)][hashtable]$Directory)
    $json = Invoke-OgwaADReader -RequestJson (ConvertTo-Json -InputObject $Request -Depth 8) -Directory $Directory -ObservedAt $observedAt
    ConvertFrom-Json -InputObject $json
}

function ConvertTo-CanonicalJson {
    param([Parameter(Mandatory)][string]$Json)
    ConvertTo-Json -InputObject (ConvertFrom-Json -InputObject $Json) -Depth 32 -Compress
}

function Invoke-InReader {
    # Calls a private function of the worker module.
    param([Parameter(Mandatory)][scriptblock]$Script, [object[]]$ArgumentList = @())
    & $reader $Script @ArgumentList
}

# --- Golden scenarios ------------------------------------------------------------------

$forest = New-SyntheticForest
$guidOf = { param($domain, $sam) (Get-SyntheticObject -Forest $forest -Domain $domain -Sam $sam).Guid }
$scenarios = [ordered]@{
    'unique-group'                          = @{ Request = New-Request -By objectGUID -Value (& $guidOf $corp 'SYNTH-App-Payroll-Users') }
    'ambiguous-name'                        = @{ Request = New-Request -By name -Value 'SYNTH-App-Finance' }
    'not-found'                             = @{ Request = New-Request -By objectGUID -Value '5e7e7000-0000-4000-8000-000000999999' }
    'unreachable-domain'                    = @{ Request = New-Request -By samAccountName -Value 'SYNTH-App-Claims'; Unreachable = @($apac) }
    'nested-group'                          = @{ Request = New-Request -By objectGUID -Value (& $guidOf $corp 'SYNTH-Nested-Parent') }
    'primary-group-dependency'              = @{ Request = New-Request -By objectSid -Value (Get-SyntheticObject -Forest $forest -Domain $corp -Sam 'SYNTH-Primary-Group-Contractors').Sid }
    'protected-group'                       = @{ Request = New-Request -By objectGUID -Value (& $guidOf $corp 'SYNTH-Tier0-Operators') }
    'normal-empty-group'                    = @{ Request = New-Request -By distinguishedName -Value (Get-SyntheticObject -Forest $forest -Domain $corp -Sam 'SYNTH-Legacy-Empty').Dn }
    'resolved-with-unreachable-parent-domain' = @{ Request = New-Request -By objectGUID -Value (& $guidOf $corp 'SYNTH-Legacy-Empty'); Unreachable = @($apac) }
}

foreach ($scenarioName in $scenarios.Keys) {
    Test-Case "golden: $scenarioName" {
        $scenario = $scenarios[$scenarioName]
        $unreachable = if ($scenario.ContainsKey('Unreachable')) { $scenario.Unreachable } else { @() }
        $directory = New-FakeADDirectory -Forest $forest -UnreachableDomains $unreachable
        $json = Invoke-OgwaADReader -RequestJson (ConvertTo-Json -InputObject $scenario.Request -Depth 8) -Directory $directory -ObservedAt $observedAt
        $path = Join-Path $fixtureDir "$scenarioName.json"
        if ($UpdateGolden) {
            [System.IO.File]::WriteAllText($path, ($json -replace "`r`n", "`n") + "`n", (New-Object System.Text.UTF8Encoding $false))
        }
        Assert-True (Test-Path -LiteralPath $path) "missing golden file $path (run with -UpdateGolden)"
        $expected = ConvertTo-CanonicalJson ([System.IO.File]::ReadAllText($path))
        Assert-Equal $expected (ConvertTo-CanonicalJson $json) "report differs from $scenarioName.json"
    }
}

Test-Case 'scenario outcomes match their names' {
    $statuses = @{}
    foreach ($scenarioName in $scenarios.Keys) {
        $statuses[$scenarioName] = (ConvertFrom-Json ([System.IO.File]::ReadAllText((Join-Path $fixtureDir "$scenarioName.json")))).resolution.status
    }
    Assert-Equal 'Resolved' $statuses['unique-group']
    Assert-Equal 'Ambiguous' $statuses['ambiguous-name']
    Assert-Equal 'NotFound' $statuses['not-found']
    Assert-Equal 'Inconclusive' $statuses['unreachable-domain']
    foreach ($scenarioName in 'nested-group', 'primary-group-dependency', 'protected-group', 'normal-empty-group', 'resolved-with-unreachable-parent-domain') {
        Assert-Equal 'Resolved' $statuses[$scenarioName] $scenarioName
    }
}

# --- Semantics ---------------------------------------------------------------------------

Test-Case 'nested expansion crosses domains, counts principals once, and detects the cycle' {
    $report = Get-Report (New-Request -By objectGUID -Value (& $guidOf $corp 'SYNTH-Nested-Parent')) (New-FakeADDirectory -Forest $forest)
    Assert-Equal 1 $report.directMembers.count
    Assert-Equal 1 $report.directMembers.byClass.group
    Assert-Equal 'Complete' $report.nestedMembers.status
    Assert-Equal 2 $report.nestedMembers.groupsTraversed
    Assert-Equal 2 $report.nestedMembers.principalCount
    Assert-True $report.nestedMembers.cycleDetected 'cycle not detected'
    # Both parents live in emea: the domain-local resource group, and the grandchild that
    # closes the cycle.
    Assert-Equal 2 $report.memberOf.count
    Assert-Equal "$emea,$emea" ((@($report.memberOf.parents) | ForEach-Object { $_.domain }) -join ',')
}

Test-Case 'primary-group references are reported although the member attribute is empty' {
    $report = Get-Report $scenarios['primary-group-dependency'].Request (New-FakeADDirectory -Forest $forest)
    Assert-Equal 0 $report.directMembers.count
    Assert-Equal 2 $report.primaryGroupReferences.count
    Assert-Equal 4108 $report.primaryGroupReferences.primaryGroupToken
}

Test-Case 'protected group reports adminCount and nesting in a well-known group' {
    $report = Get-Report $scenarios['protected-group'].Request (New-FakeADDirectory -Forest $forest)
    $indicators = @($report.protection.indicators)
    Assert-True ($indicators -contains 'AdminCount') 'AdminCount missing'
    Assert-True ($indicators -contains 'NestedInWellKnownGroup:S-1-5-21-1000000001-1000000002-1000000003-512') 'nesting indicator missing'
    Assert-Equal 'Determined' $report.protection.status
}

Test-Case 'unreadable ProtectedFromAccidentalDeletion makes protection Undetermined' {
    $local = New-SyntheticForest
    (Get-SyntheticObject -Forest $local -Domain $corp -Sam 'SYNTH-Legacy-Empty').Protected = $null
    $report = Get-Report (New-Request -By samAccountName -Value 'SYNTH-Legacy-Empty' -Domain $corp) (New-FakeADDirectory -Forest $local)
    Assert-Equal 'Resolved' $report.resolution.status
    Assert-Equal $null $report.group.protectedFromAccidentalDeletion
    Assert-Equal 'Undetermined' $report.protection.status
}

Test-Case 'a name match is Inconclusive while any domain in scope is unreachable' {
    $report = Get-Report $scenarios['unreachable-domain'].Request (New-FakeADDirectory -Forest $forest -UnreachableDomains @($apac))
    Assert-Equal 'Inconclusive' $report.resolution.status
    Assert-Equal 1 @($report.resolution.candidates).Count
    Assert-Equal $null $report.group
    Assert-Equal 'NotApplicable' $report.directMembers.status
    Assert-Equal $false (@($report.domains | Where-Object { $_.dnsName -eq $apac }))[0].reachable
}

Test-Case 'a domain hint limits a name lookup to that domain' {
    $directory = New-FakeADDirectory -Forest $forest -UnreachableDomains @($apac)
    $report = Get-Report (New-Request -By samAccountName -Value 'SYNTH-App-Claims' -Domain $corp -Include @{ directMembers = $false; nestedMembers = $false; primaryGroupReferences = $false; memberOf = $false }) $directory
    Assert-Equal 'Resolved' $report.resolution.status
    Assert-True (-not ($directory.Log -contains "GetDomain:$apac")) 'apac was contacted'
}

Test-Case 'a SID lookup searches only the domain that owns the SID' {
    $directory = New-FakeADDirectory -Forest $forest
    $report = Get-Report $scenarios['primary-group-dependency'].Request $directory
    Assert-Equal 'Resolved' $report.resolution.status
    $searches = @($directory.Log | Where-Object { $_ -like 'FindGroups:*' })
    Assert-Equal 1 $searches.Count
    Assert-Equal "FindGroups:$corp" $searches[0]
}

Test-Case 'a DN lookup searches only the DN''s domain' {
    $directory = New-FakeADDirectory -Forest $forest
    [void](Get-Report $scenarios['normal-empty-group'].Request $directory)
    Assert-Equal "FindGroups:$corp" (@($directory.Log | Where-Object { $_ -like 'FindGroups:*' }) -join ',')
}

Test-Case 'excluded sections are NotRequested and are not queried' {
    $directory = New-FakeADDirectory -Forest $forest
    $include = @{ directMembers = $false; nestedMembers = $false; primaryGroupReferences = $false; memberOf = $false }
    $report = Get-Report (New-Request -By objectGUID -Value (& $guidOf $corp 'SYNTH-App-Payroll-Users') -Include $include) $directory
    foreach ($section in 'directMembers', 'nestedMembers', 'primaryGroupReferences', 'memberOf') {
        Assert-Equal 'NotRequested' $report.$section.status $section
    }
    Assert-Equal 'Undetermined' $report.protection.status
    $operations = @($directory.Log | ForEach-Object { ($_ -split ':')[0] } | Sort-Object -Unique)
    Assert-Equal 'FindGroups,GetDomain,GetForest,GetGroup' ($operations -join ',')
}

Test-Case 'direct members beyond maxDirectMembers are counted but marked Truncated' {
    $report = Get-Report (New-Request -By objectGUID -Value (& $guidOf $corp 'SYNTH-App-Payroll-Users') -Limits @{ maxDirectMembers = 1 }) (New-FakeADDirectory -Forest $forest)
    Assert-Equal 2 $report.directMembers.count
    Assert-Equal 'Truncated' $report.directMembers.status
    Assert-Equal 1 $report.directMembers.byClass.user
    Assert-Equal 'Truncated' $report.nestedMembers.status
}

Test-Case 'nesting beyond maxNestedGroups is Truncated with a lower-bound count' {
    $report = Get-Report (New-Request -By objectGUID -Value (& $guidOf $corp 'SYNTH-Nested-Parent') -Limits @{ maxNestedGroups = 1 }) (New-FakeADDirectory -Forest $forest)
    Assert-Equal 'Truncated' $report.nestedMembers.status
    Assert-Equal 1 $report.nestedMembers.groupsTraversed
    Assert-True $report.nestedMembers.principalCountIsLowerBound 'count should be a lower bound'
    Assert-True ($report.nestedMembers.unexpandedReferences -ge 1) 'unexpanded references not counted'
}

Test-Case 'primary-group counting stops at maxPrimaryGroupReferences' {
    $request = New-Request -By objectSid -Value $scenarios['primary-group-dependency'].Request.lookup.value -Limits @{ maxPrimaryGroupReferences = 1 }
    $report = Get-Report $request (New-FakeADDirectory -Forest $forest)
    Assert-Equal 'Truncated' $report.primaryGroupReferences.status
    Assert-Equal 1 $report.primaryGroupReferences.count
    Assert-True $report.primaryGroupReferences.countIsLowerBound 'count should be a lower bound'
}

Test-Case 'a domain that stops answering mid-run leaves memberOf Partial' {
    $overrides = @{
        FindParentGroups = {
            param($arguments)
            if ($arguments[0].DnsName -eq 'emea.corp.synthetic.example') { throw 'OGWA-UNREACHABLE: synthetic timeout' }
            @()
        }
    }
    $report = Get-Report $scenarios['normal-empty-group'].Request (New-FakeADDirectory -Forest $forest -Overrides $overrides)
    Assert-Equal 'Partial' $report.memberOf.status
    Assert-True (@($report.memberOf.unsearchedDomains) -contains $emea) 'emea should be unsearched'
    Assert-Equal 'Undetermined' $report.protection.status
}

Test-Case 'a query error is Failed, not NotFound' {
    $overrides = @{ FindGroups = { param($arguments) throw 'synthetic LDAP error' } }
    $report = Get-Report $scenarios['not-found'].Request (New-FakeADDirectory -Forest $forest -Overrides $overrides)
    Assert-Equal 'Failed' $report.resolution.status
}

Test-Case 'a group that changes between search and read is Failed' {
    $overrides = @{ GetGroup = { param($arguments) @{ ObjectGUID = [guid]'5e7e7000-0000-4000-8000-000000000001'; ObjectSid = 'S-1-5-21-1000000001-1000000002-1000000003-9999' } } }
    $report = Get-Report $scenarios['unique-group'].Request (New-FakeADDirectory -Forest $forest -Overrides $overrides)
    Assert-Equal 'Failed' $report.resolution.status
    Assert-Equal $null $report.group
}

Test-Case 'an unreachable forest is Inconclusive' {
    $overrides = @{ GetForest = { param($arguments) throw 'OGWA-UNREACHABLE: synthetic forest unavailable' } }
    $report = Get-Report $scenarios['unique-group'].Request (New-FakeADDirectory -Forest $forest -Overrides $overrides)
    Assert-Equal 'Inconclusive' $report.resolution.status
}

# --- Request validation (fails before any directory call) --------------------------------

$invalidRequests = [ordered]@{
    'unknown top-level key'      = { $r = New-Request -By objectGUID -Value (& $guidOf $corp 'SYNTH-Legacy-Empty'); $r.extra = 1; $r }
    'unknown lookup key'         = { $r = New-Request -By objectGUID -Value (& $guidOf $corp 'SYNTH-Legacy-Empty'); $r.lookup.wildcard = $true; $r }
    'wrong schema'               = { $r = New-Request -By objectGUID -Value (& $guidOf $corp 'SYNTH-Legacy-Empty'); $r.schema = 'ogwa.ad.group-read-request/v2'; $r }
    'unknown lookup kind'        = { New-Request -By mail -Value 'x@synthetic.example' }
    'malformed GUID'             = { New-Request -By objectGUID -Value 'not-a-guid' }
    'malformed SID'              = { New-Request -By objectSid -Value 'S-1-5-21-x' }
    'control character'          = { New-Request -By name -Value "SYNTH`tGroup" }
    'surrounding space'          = { New-Request -By name -Value ' SYNTH-Legacy-Empty' }
    'limit above ceiling'        = { New-Request -By name -Value 'SYNTH-Legacy-Empty' -Limits @{ maxDirectMembers = 5001 } }
    'limit below one'            = { New-Request -By name -Value 'SYNTH-Legacy-Empty' -Limits @{ maxNestedGroups = 0 } }
    'non-integer limit'          = { New-Request -By name -Value 'SYNTH-Legacy-Empty' -Limits @{ maxNestedGroups = '5' } }
    'non-boolean include'        = { New-Request -By name -Value 'SYNTH-Legacy-Empty' -Include @{ memberOf = 'yes' } }
    'nested without direct'      = { New-Request -By name -Value 'SYNTH-Legacy-Empty' -Include @{ directMembers = $false; nestedMembers = $true } }
    'domain outside the forest'  = { New-Request -By name -Value 'SYNTH-Legacy-Empty' -Domain 'other.synthetic.example' }
    'DN outside the forest'      = { New-Request -By distinguishedName -Value 'CN=SYNTH-X,DC=other,DC=synthetic,DC=example' }
}
foreach ($case in $invalidRequests.Keys) {
    Test-Case "invalid request: $case" {
        $directory = New-FakeADDirectory -Forest $forest
        $report = Get-Report (& $invalidRequests[$case]) $directory
        Assert-Equal 'InvalidRequest' $report.resolution.status
        Assert-Equal $null $report.group
        Assert-True (@($directory.Log | Where-Object { $_ -like 'FindGroups*' }).Count -eq 0) 'the directory was searched'
    }
}

Test-Case 'invalid JSON and oversized requests still produce a report' {
    $directory = New-FakeADDirectory -Forest $forest
    foreach ($text in @('{not json', ('x' * 70000), '')) {
        $report = ConvertFrom-Json (Invoke-OgwaADReader -RequestJson $text -Directory $directory -ObservedAt $observedAt)
        Assert-Equal 'InvalidRequest' $report.resolution.status
        Assert-Equal 'ogwa.ad.group-report/v1' $report.schema
    }
    Assert-Equal 0 $directory.Log.Count 'the directory was contacted'
}

Test-Case 'GUID lookups are canonicalized' {
    $guid = & $guidOf $corp 'SYNTH-Legacy-Empty'
    $report = Get-Report (New-Request -By objectGUID -Value ('{' + $guid.ToUpperInvariant() + '}')) (New-FakeADDirectory -Forest $forest)
    Assert-Equal $guid $report.request.lookup.value
    Assert-Equal 'Resolved' $report.resolution.status
}

# --- LDAP filters ------------------------------------------------------------------------

Test-Case 'LDAP filter values are escaped per RFC 4515' {
    Assert-Equal 'a\2a' (Invoke-InReader { ConvertTo-OgwaLdapFilterValue 'a*' })
    Assert-Equal 'x\29\28objectClass=\2a' (Invoke-InReader { ConvertTo-OgwaLdapFilterValue 'x)(objectClass=*' })
    Assert-Equal 'CN=Smith\5c, John' (Invoke-InReader { ConvertTo-OgwaLdapFilterValue 'CN=Smith\, John' })
    Assert-Equal 'a\00b' (Invoke-InReader { ConvertTo-OgwaLdapFilterValue ("a" + [char]0 + "b") })
}

Test-Case 'objectGUID filters use escaped bytes in GUID byte order' {
    $value = Invoke-InReader { ConvertTo-OgwaLdapGuidValue -Guid '01020304-0506-0708-090a-0b0c0d0e0f10' }
    Assert-Equal '\04\03\02\01\06\05\08\07\09\0a\0b\0c\0d\0e\0f\10' $value
}

Test-Case 'lookup filters are exact matches on groups only' {
    Assert-Equal '(&(objectCategory=group)(sAMAccountName=SYNTH\2a))' (Invoke-InReader { New-OgwaGroupLookupFilter -By samAccountName -Value 'SYNTH*' })
    Assert-Equal '(&(objectCategory=group)(|(name=a\29b)(sAMAccountName=a\29b)))' (Invoke-InReader { New-OgwaGroupLookupFilter -By name -Value 'a)b' })
    Assert-Equal '(&(objectCategory=group)(objectSid=S-1-5-32-544))' (Invoke-InReader { New-OgwaGroupLookupFilter -By objectSid -Value 'S-1-5-32-544' })
}

Test-Case 'DNs map to the most specific forest domain' {
    $domains = [string[]]@($corp, $emea, $apac)
    Assert-Equal $emea (Invoke-InReader { param($d) Get-OgwaOwningDomain -DistinguishedName 'CN=X,OU=Y,DC=emea,DC=corp,DC=synthetic,DC=example' -DomainNames $d } @(, $domains))
    Assert-Equal $corp (Invoke-InReader { param($d) Get-OgwaOwningDomain -DistinguishedName 'CN=X,DC=corp,DC=synthetic,DC=example' -DomainNames $d } @(, $domains))
    Assert-Equal $null (Invoke-InReader { param($d) Get-OgwaOwningDomain -DistinguishedName 'CN=X,DC=notcorp,DC=synthetic,DC=example' -DomainNames $d } @(, $domains))
}

# --- Default accessor --------------------------------------------------------------------

Test-Case 'without the ActiveDirectory module the reader fails closed and contacts nothing' {
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Write-Host '      (skipped: the ActiveDirectory module is installed, and this test must not reach a directory)'
        return
    }
    $report = ConvertFrom-Json (Invoke-OgwaADReader -RequestJson (ConvertTo-Json -InputObject $scenarios['unique-group'].Request -Depth 8) -ObservedAt $observedAt)
    Assert-Equal 'Failed' $report.resolution.status
    Assert-True ($report.resolution.error -like '*ActiveDirectory*') 'error should name the missing module'
}

Write-Host ''
Write-Host ("{0} passed, {1} failed (PowerShell {2})" -f $script:passed, $script:failures.Count, $PSVersionTable.PSVersion)
if ($script:failures.Count -gt 0) {
    $script:failures | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    exit 1
}
exit 0
