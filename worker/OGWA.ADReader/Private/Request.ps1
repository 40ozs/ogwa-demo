# Request validation. Anything unexpected is refused before the directory is contacted.

$script:IncludeKeys = @('directMembers', 'nestedMembers', 'primaryGroupReferences', 'memberOf')
$script:MaxLookupValueLength = 1024

function ConvertTo-OgwaReadRequest {
    # Validates a request (hashtable or parsed JSON) and returns the normalized form, with
    # every include flag and limit filled in. Throws an OGWA-INVALID error otherwise.
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()][object]$Request)

    Assert-OgwaObject -InputObject $Request -Where 'request' -Allowed @('schema', 'lookup', 'include', 'limits')
    if ((Get-OgwaValue $Request 'schema') -cne $script:Contract.requestSchema) {
        throw ($script:InvalidPrefix + "request.schema must be '$($script:Contract.requestSchema)'")
    }

    $lookup = Get-OgwaValue $Request 'lookup'
    Assert-OgwaObject -InputObject $lookup -Where 'lookup' -Allowed @('by', 'value', 'domain')

    $by = Get-OgwaValue $lookup 'by'
    if (-not ($by -is [string]) -or @($script:Contract.lookupKinds) -cnotcontains $by) {
        throw ($script:InvalidPrefix + ('lookup.by must be one of: ' + (@($script:Contract.lookupKinds) -join ', ')))
    }

    $value = Get-OgwaValue $lookup 'value'
    if (-not ($value -is [string]) -or $value.Length -eq 0 -or $value.Length -gt $script:MaxLookupValueLength -or
        $value -match '[\x00-\x1f\x7f]' -or $value.Trim() -ne $value) {
        throw ($script:InvalidPrefix + "lookup.value must be 1-$($script:MaxLookupValueLength) characters, without control characters or surrounding spaces")
    }
    switch -CaseSensitive ($by) {
        'objectGUID' {
            $parsed = [guid]::Empty
            if (-not [guid]::TryParse($value, [ref]$parsed)) { throw ($script:InvalidPrefix + 'lookup.value is not a GUID') }
            $value = $parsed.ToString('D')
        }
        'objectSid' {
            if ($value -cnotmatch $script:SidPattern) { throw ($script:InvalidPrefix + 'lookup.value is not a SID (S-1-...)') }
        }
        'distinguishedName' {
            if ($value -notmatch '(^|,)DC=') { throw ($script:InvalidPrefix + 'lookup.value is not a distinguished name') }
        }
    }

    $domain = Get-OgwaValue $lookup 'domain'
    if ($null -ne $domain) {
        if (-not ($domain -is [string])) { throw ($script:InvalidPrefix + 'lookup.domain must be a DNS domain name or null') }
        $domain = $domain.ToLowerInvariant()
        if ($domain -cnotmatch $script:DnsNamePattern) { throw ($script:InvalidPrefix + 'lookup.domain must be a DNS domain name or null') }
    }

    $includeInput = Get-OgwaValue $Request 'include'
    if ($null -ne $includeInput) { Assert-OgwaObject -InputObject $includeInput -Where 'include' -Allowed $script:IncludeKeys }
    $include = [ordered]@{}
    foreach ($key in $script:IncludeKeys) {
        $flag = Get-OgwaValue $includeInput $key
        if ($null -eq $flag) { $flag = $true }
        elseif (-not ($flag -is [bool])) { throw ($script:InvalidPrefix + "include.$key must be true or false") }
        $include[$key] = $flag
    }
    if ($include.nestedMembers -and -not $include.directMembers) {
        throw ($script:InvalidPrefix + 'include.nestedMembers requires include.directMembers')
    }

    $limitNames = @($script:Contract.limits.PSObject.Properties | ForEach-Object { $_.Name })
    $limitsInput = Get-OgwaValue $Request 'limits'
    if ($null -ne $limitsInput) { Assert-OgwaObject -InputObject $limitsInput -Where 'limits' -Allowed $limitNames }
    $limits = [ordered]@{}
    foreach ($name in $limitNames) {
        $bounds = $script:Contract.limits.$name
        $limit = Get-OgwaValue $limitsInput $name
        if ($null -eq $limit) { $limit = $bounds.default }
        elseif (-not ($limit -is [int] -or $limit -is [long]) -or $limit -lt 1 -or $limit -gt $bounds.ceiling) {
            throw ($script:InvalidPrefix + "limits.$name must be a whole number from 1 to $($bounds.ceiling)")
        }
        $limits[$name] = [int]$limit
    }

    [ordered]@{
        schema  = $script:Contract.requestSchema
        lookup  = [ordered]@{ by = $by; value = $value; domain = $domain }
        include = $include
        limits  = $limits
    }
}
