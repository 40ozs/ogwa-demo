# Shared helpers: value conversion, LDAP escaping, DN-to-domain mapping, error text.

$script:UnreachablePrefix = 'OGWA-UNREACHABLE: '
$script:InvalidPrefix = 'OGWA-INVALID: '
$script:MaxErrorText = 300
$script:DnBatchSize = 50
$script:SidPattern = '^S-1-[0-9]+(-[0-9]+)+$'
$script:BuiltinSidPrefix = 'S-1-5-32-'
# Domain RIDs below 1000 are well-known (Domain Admins 512, Schema Admins 518, ...).
$script:FirstOrdinaryRid = 1000
$script:DnsNamePattern = '^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$'

function ConvertTo-OgwaLdapFilterValue {
    # RFC 4515 escaping, so "a*" or "x)(objectClass=*" is matched literally and can
    # never widen a filter.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)

    $builder = New-Object System.Text.StringBuilder
    foreach ($character in $Value.ToCharArray()) {
        switch ([int]$character) {
            0x5C { [void]$builder.Append('\5c') }
            0x2A { [void]$builder.Append('\2a') }
            0x28 { [void]$builder.Append('\28') }
            0x29 { [void]$builder.Append('\29') }
            0x00 { [void]$builder.Append('\00') }
            default { [void]$builder.Append($character) }
        }
    }
    $builder.ToString()
}

function ConvertTo-OgwaLdapGuidValue {
    # objectGUID is binary; an LDAP filter matches it as escaped bytes in GUID byte order.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][guid]$Guid)

    -join ($Guid.ToByteArray() | ForEach-Object { '\{0:x2}' -f $_ })
}

function ConvertTo-OgwaDomainDn {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$DnsName)

    'DC=' + (($DnsName -split '\.') -join ',DC=')
}

function Get-OgwaOwningDomain {
    # The forest domain whose DN is the longest suffix of the given DN, so a child
    # domain wins over its parent. $null when no forest domain owns the DN.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DistinguishedName,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$DomainNames
    )

    $best = $null
    $bestLength = -1
    foreach ($name in $DomainNames) {
        $suffix = ConvertTo-OgwaDomainDn -DnsName $name
        $isMatch = $DistinguishedName.Equals($suffix, [StringComparison]::OrdinalIgnoreCase) -or
            $DistinguishedName.EndsWith(',' + $suffix, [StringComparison]::OrdinalIgnoreCase)
        if ($isMatch -and $suffix.Length -gt $bestLength) {
            $best = $name
            $bestLength = $suffix.Length
        }
    }
    $best
}

function Get-OgwaValue {
    # Reads a key or property from a hashtable, an ordered dictionary or an object.
    # Missing values are $null. Arrays are written to the pipeline, so wrap in @().
    [CmdletBinding()]
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        return $null
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    $property.Value
}

function Test-OgwaIsObject {
    param([AllowNull()][object]$InputObject)

    $null -ne $InputObject -and (
        $InputObject -is [System.Collections.IDictionary] -or
        $InputObject.GetType().FullName -eq 'System.Management.Automation.PSCustomObject')
}

function Assert-OgwaObject {
    # Fails closed on anything that is not an object or that carries an unknown key.
    [CmdletBinding()]
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Where,
        [Parameter(Mandatory)][string[]]$Allowed
    )

    if (-not (Test-OgwaIsObject $InputObject)) {
        throw ($script:InvalidPrefix + "$Where must be a JSON object")
    }
    $keys = if ($InputObject -is [System.Collections.IDictionary]) {
        @($InputObject.Keys | ForEach-Object { [string]$_ })
    }
    else {
        @($InputObject.PSObject.Properties | ForEach-Object { $_.Name })
    }
    foreach ($key in $keys) {
        if ($Allowed -cnotcontains $key) {
            throw ($script:InvalidPrefix + "$Where has an unknown key '$key'")
        }
    }
}

function ConvertTo-OgwaUtcText {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return $null }
    ([datetime]$Value).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-OgwaGuidText {
    # Canonical lowercase GUID text ("D" format).
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [guid]) { return $Value.ToString('D') }
    if ($Value -is [byte[]]) { return (New-Object -TypeName System.Guid -ArgumentList @(, $Value)).ToString('D') }
    ([guid][string]$Value).ToString('D')
}

function ConvertTo-OgwaSidText {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return $null }
    $text = if ($Value -is [System.Security.Principal.SecurityIdentifier]) { $Value.Value } else { [string]$Value }
    if ($text -cnotmatch $script:SidPattern) { throw "the directory returned a value that is not a SID" }
    $text
}

function Get-OgwaRid {
    param([AllowNull()][string]$Sid)

    if (-not $Sid -or $Sid -cnotmatch $script:SidPattern) { return $null }
    [long]$Sid.Substring($Sid.LastIndexOf('-') + 1)
}

function Test-OgwaWellKnownSid {
    # Builtin-domain SIDs and domain RIDs below 1000 identify well-known groups in any
    # language, unlike their names.
    param([AllowNull()][string]$Sid)

    $rid = Get-OgwaRid -Sid $Sid
    $null -ne $rid -and ($Sid.StartsWith($script:BuiltinSidPrefix) -or $rid -lt $script:FirstOrdinaryRid)
}

function Get-OgwaErrorText {
    # A short, single-line error text without OGWA markers.
    param([Parameter(Mandatory)][AllowNull()][object]$ErrorRecord)

    $message = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) {
        [string]$ErrorRecord.Exception.Message
    }
    else {
        [string]$ErrorRecord
    }
    foreach ($prefix in @($script:UnreachablePrefix, $script:InvalidPrefix)) {
        if ($message.StartsWith($prefix)) { $message = $message.Substring($prefix.Length) }
    }
    $message = ($message -replace '\s+', ' ').Trim()
    if (-not $message) { $message = 'unspecified error' }
    if ($message.Length -gt $script:MaxErrorText) { $message = $message.Substring(0, $script:MaxErrorText - 3) + '...' }
    $message
}

function Join-OgwaErrorText {
    param([AllowNull()][AllowEmptyCollection()][string[]]$Messages)

    $items = @($Messages | Where-Object { $_ })
    if ($items.Count -eq 0) { return $null }
    Get-OgwaErrorText -ErrorRecord ($items -join '; ')
}

function Test-OgwaUnreachableError {
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)

    ([string]$ErrorRecord.Exception.Message).StartsWith($script:UnreachablePrefix)
}

function Test-OgwaInvalidError {
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)

    ([string]$ErrorRecord.Exception.Message).StartsWith($script:InvalidPrefix)
}

function Invoke-OgwaDirectory {
    # Runs one read operation of the directory accessor.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Directory,
        [Parameter(Mandatory)][string]$Operation,
        [object[]]$ArgumentList = @()
    )

    $operationBlock = $Directory[$Operation]
    if (-not ($operationBlock -is [scriptblock])) {
        throw "the directory accessor has no '$Operation' operation"
    }
    & $operationBlock @ArgumentList
}

function Sort-OgwaByText {
    # Ordinal, case-insensitive sort, identical on Windows PowerShell and PowerShell 7.
    param(
        [AllowEmptyCollection()][object[]]$Items,
        [Parameter(Mandatory)][scriptblock]$Key
    )

    if (-not $Items -or $Items.Count -eq 0) { return }
    [string[]]$keys = @($Items | ForEach-Object { [string](& $Key $_) })
    [object[]]$values = @($Items)
    [Array]::Sort($keys, $values, [StringComparer]::OrdinalIgnoreCase)
    $values
}

function Get-OgwaSectionStatus {
    param([bool]$Truncated, [bool]$Partial)

    if ($Partial) { 'Partial' } elseif ($Truncated) { 'Truncated' } else { 'Complete' }
}
