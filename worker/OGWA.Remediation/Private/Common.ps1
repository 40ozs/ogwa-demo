# Shared helpers: explicit-target validation, synthetic-identity rules, and the result.

$script:MaxValueLength = 1024
$script:MaxDetail = 300
$script:SidPattern = '^S-1-[0-9]+(-[0-9]+)+$'
$script:BuiltinSidPrefix = 'S-1-5-32-'
# Domain RIDs below 1000 are well-known (Domain Admins 512, Schema Admins 518, ...).
$script:FirstOrdinaryRid = 1000
$script:GuidPattern = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
$script:DnsNamePattern = '^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$'
$script:OktaIdPattern = '^[A-Za-z0-9]{1,64}$'
$script:CorrelationPattern = '^[A-Za-z0-9._:-]{1,100}$'
# A value containing any of these is a pattern, not one explicit target.
$script:WildcardPattern = '[*?%\[\]]'
$script:ControlPattern = '[\x00-\x1f\x7f]'
# Synthetic identities only: the reserved .example domain (RFC 2606) and SYNTH Okta ids.
$script:SyntheticDomainSuffix = 'synthetic.example'
$script:SyntheticOktaAppPrefix = '0oaSYNTH'
$script:SyntheticOktaGroupPrefix = '00gSYNTH'

function Get-OgwaDetailText {
    param([AllowNull()][object]$Text)

    $message = (([string]$Text) -replace '\s+', ' ').Trim()
    if (-not $message) { $message = 'no detail' }
    if ($message.Length -gt $script:MaxDetail) { $message = $message.Substring(0, $script:MaxDetail - 3) + '...' }
    $message
}

function ConvertTo-OgwaUtcText {
    param([Parameter(Mandatory)][datetime]$Value)

    $Value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-OgwaDomainDn {
    param([Parameter(Mandatory)][string]$DnsName)

    'DC=' + (($DnsName -split '\.') -join ',DC=')
}

function Test-OgwaDnInDomain {
    # True when the DN lies strictly inside the domain whose DN is $DomainDn.
    param([Parameter(Mandatory)][string]$DistinguishedName, [Parameter(Mandatory)][string]$DomainDn)

    $DistinguishedName.EndsWith(',' + $DomainDn, [StringComparison]::OrdinalIgnoreCase)
}

function Split-OgwaDn {
    # (first RDN, parent DN), splitting at the first comma that is not escaped.
    param([Parameter(Mandatory)][string]$DistinguishedName)

    $escaped = $false
    for ($index = 0; $index -lt $DistinguishedName.Length; $index++) {
        $character = $DistinguishedName[$index]
        if ($escaped) { $escaped = $false }
        elseif ($character -eq '\') { $escaped = $true }
        elseif ($character -eq ',') {
            return @($DistinguishedName.Substring(0, $index), $DistinguishedName.Substring($index + 1))
        }
    }
    @($DistinguishedName, '')
}

function Test-OgwaSyntheticDomain {
    param([AllowNull()][string]$Domain)

    $null -ne $Domain -and ($Domain -ceq $script:SyntheticDomainSuffix -or $Domain.EndsWith('.' + $script:SyntheticDomainSuffix))
}

function Test-OgwaWellKnownSid {
    # Builtin-domain SIDs and domain RIDs below 1000 identify well-known groups in any language.
    param([AllowNull()][string]$Sid)

    if (-not $Sid -or $Sid -cnotmatch $script:SidPattern) { return $false }
    $rid = [long]$Sid.Substring($Sid.LastIndexOf('-') + 1)
    $Sid.StartsWith($script:BuiltinSidPrefix) -or $rid -lt $script:FirstOrdinaryRid
}

function Get-OgwaValueProblem {
    # $null when the value is one explicit identifier; otherwise the block reason.
    param([AllowNull()][object]$Value)

    if (-not ($Value -is [string]) -or $Value.Length -eq 0 -or $Value.Length -gt $script:MaxValueLength -or
        $Value -match $script:ControlPattern -or $Value.Trim() -ne $Value) {
        return 'INVALID_REQUEST'
    }
    if ($Value -match $script:WildcardPattern) { return 'WILDCARD_TARGET' }
    $null
}

# --- the result ----------------------------------------------------------------------------

function New-OgwaRemediationResult {
    param(
        [AllowNull()][string]$Operation,
        [AllowNull()][AllowEmptyString()][string]$CorrelationId,
        [Parameter(Mandatory)][datetime]$ObservedAt
    )

    # Untyped locals: assigning $null to a [string] parameter would store "" instead.
    $operationValue = $null
    if ($Operation) { $operationValue = $Operation }
    $correlationValue = $null
    if ($CorrelationId -and $CorrelationId -cmatch $script:CorrelationPattern) { $correlationValue = $CorrelationId }
    [ordered]@{
        schema             = $script:Contract.resultSchema
        worker             = [ordered]@{ name = $script:Contract.workerName; version = $script:Contract.workerVersion }
        operation          = $operationValue
        outcome            = $null
        executed           = $false
        productionMutation = $false
        correlationId      = $correlationValue
        observedAt         = ConvertTo-OgwaUtcText -Value $ObservedAt
        target             = $null
        checks             = New-Object System.Collections.Generic.List[object]
        plannedChanges     = New-Object System.Collections.Generic.List[object]
        blockedReasons     = New-Object System.Collections.Generic.List[string]
    }
}

function Add-OgwaCheck {
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Result,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][bool]$Passed,
        [AllowNull()][object]$Detail
    )

    if (@($script:Contract.checkCodes) -cnotcontains $Code) { throw "unknown check code $Code" }
    $Result.checks.Add([ordered]@{ code = $Code; passed = $Passed; detail = Get-OgwaDetailText $Detail })
}

function Add-OgwaBlockReason {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Result, [Parameter(Mandatory)][string]$Reason)

    if (@($script:Contract.blockReasons) -cnotcontains $Reason) { throw "unknown block reason $Reason" }
    if (-not $Result.blockedReasons.Contains($Reason)) { $Result.blockedReasons.Add($Reason) }
}

function Stop-OgwaRemediation {
    # Records a failed check and the reason it blocks the request.
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Result,
        [Parameter(Mandatory)][string]$Code,
        [Parameter(Mandatory)][string]$Reason,
        [AllowNull()][object]$Detail
    )

    Add-OgwaCheck -Result $Result -Code $Code -Passed $false -Detail $Detail
    Add-OgwaBlockReason -Result $Result -Reason $Reason
}

function Complete-OgwaRemediation {
    # The finished result: Blocked when any reason was recorded, otherwise $Outcome with the
    # one planned change. executed and productionMutation stay the literal $false they were
    # created with; nothing in this module assigns them.
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Result,
        [ValidateSet('WhatIf', 'ValidationOnly', 'Simulated')][string]$Outcome,
        [System.Collections.IDictionary]$Change
    )

    if ($Result.blockedReasons.Count -gt 0 -or -not $Outcome) {
        if ($Result.blockedReasons.Count -eq 0) { throw 'a remediation without an outcome must name a block reason' }
        $Result.outcome = 'Blocked'
        $Result.plannedChanges.Clear()
    }
    else {
        if ($null -eq $Change) { throw "a $Outcome result describes its change" }
        $Result.outcome = $Outcome
        $Result.plannedChanges.Add($Change)
    }
    [pscustomobject][ordered]@{
        schema             = $Result.schema
        worker             = $Result.worker
        operation          = $Result.operation
        outcome            = $Result.outcome
        executed           = $false
        productionMutation = $false
        correlationId      = $Result.correlationId
        observedAt         = $Result.observedAt
        target             = $Result.target
        checks             = [object[]]$Result.checks.ToArray()
        plannedChanges     = [object[]]$Result.plannedChanges.ToArray()
        blockedReasons     = [string[]]$Result.blockedReasons.ToArray()
    }
}

# --- explicit targets ----------------------------------------------------------------------

function Test-OgwaTargetValues {
    # Every value must be one explicit identifier. Sets $Result.target only when they are.
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Result,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Values
    )

    foreach ($key in @($Values.Keys)) {
        $problem = Get-OgwaValueProblem -Value $Values[$key]
        if ($problem) {
            $detail = if ($problem -eq 'WILDCARD_TARGET') { "$key is a pattern; a remediation names one explicit target" }
            else { "$key must be 1-$($script:MaxValueLength) characters without control characters or surrounding spaces" }
            Stop-OgwaRemediation -Result $Result -Code 'REQUEST_VALID' -Reason $problem -Detail $detail
            return $false
        }
    }
    $true
}

function Test-OgwaADTargetRequest {
    # Validates an AD target before anything is looked up.
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Result,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Values
    )

    if (-not (Test-OgwaTargetValues -Result $Result -Values $Values)) { return $false }
    $problem = $null
    $domainDn = $null
    if ($Values.objectGuid -cnotmatch $script:GuidPattern) { $problem = 'objectGuid must be a lowercase GUID in D format' }
    elseif ($Values.domain -cnotmatch $script:DnsNamePattern) { $problem = 'domain must be a lowercase DNS domain name' }
    elseif ($Values.expectedSid -cnotmatch $script:SidPattern) { $problem = 'expectedSid must be a SID (S-1-...)' }
    else {
        $domainDn = ConvertTo-OgwaDomainDn -DnsName $Values.domain
        if (-not (Test-OgwaDnInDomain -DistinguishedName $Values.expectedDistinguishedName -DomainDn $domainDn)) {
            $problem = 'expectedDistinguishedName must lie inside the domain'
        }
        elseif ($Values.Contains('quarantineOu') -and (
                -not $Values.quarantineOu.StartsWith('OU=', [StringComparison]::OrdinalIgnoreCase) -or
                -not (Test-OgwaDnInDomain -DistinguishedName $Values.quarantineOu -DomainDn $domainDn))) {
            $problem = 'quarantineOu must be an OU inside the same domain'
        }
    }
    if ($problem) {
        Stop-OgwaRemediation -Result $Result -Code 'REQUEST_VALID' -Reason 'INVALID_REQUEST' -Detail $problem
        return $false
    }
    $Result.target = $Values
    Add-OgwaCheck -Result $Result -Code 'REQUEST_VALID' -Passed $true -Detail 'one explicit AD group, by objectGUID in its domain'
    $true
}
