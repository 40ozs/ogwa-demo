# Helpers for the default accessor (New-OgwaADDirectory). Read-only Get-* queries only.

$script:SummaryProperties = @('objectGUID', 'objectSid', 'sAMAccountName', 'name', 'objectClass', 'distinguishedName')
$script:GroupProperties = @(
    'member', 'adminCount', 'isCriticalSystemObject', 'ProtectedFromAccidentalDeletion',
    'primaryGroupToken', 'whenCreated', 'whenChanged'
)

function New-OgwaGroupLookupFilter {
    # Exact-match LDAP filter for one lookup kind. Values are escaped, so no wildcard or
    # filter fragment can be injected.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$By, [Parameter(Mandatory)][string]$Value)

    $clause = switch -CaseSensitive ($By) {
        'objectGUID' { '(objectGUID={0})' -f (ConvertTo-OgwaLdapGuidValue -Guid ([guid]$Value)) }
        'objectSid' { '(objectSid={0})' -f (ConvertTo-OgwaLdapFilterValue $Value) }
        'distinguishedName' { '(distinguishedName={0})' -f (ConvertTo-OgwaLdapFilterValue $Value) }
        'samAccountName' { '(sAMAccountName={0})' -f (ConvertTo-OgwaLdapFilterValue $Value) }
        'name' { '(|(name={0})(sAMAccountName={0}))' -f (ConvertTo-OgwaLdapFilterValue $Value) }
        default { throw "unsupported lookup kind '$By'" }
    }
    '(&(objectCategory=group){0})' -f $clause
}

function ConvertTo-OgwaSummary {
    param([Parameter(Mandatory)][object]$ADObject)

    $sid = Get-OgwaValue $ADObject 'objectSid'
    @{
        DistinguishedName = [string](Get-OgwaValue $ADObject 'DistinguishedName')
        ObjectGUID        = Get-OgwaValue $ADObject 'ObjectGUID'
        ObjectSid         = if ($sid) { $sid.Value } else { $null }
        SamAccountName    = Get-OgwaValue $ADObject 'sAMAccountName'
        Name              = Get-OgwaValue $ADObject 'Name'
        ObjectClass       = [string](Get-OgwaValue $ADObject 'ObjectClass')
    }
}

function Test-OgwaServerDown {
    # True when no domain controller answered (as opposed to a query error).
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)

    $exception = $ErrorRecord.Exception
    while ($null -ne $exception) {
        if ($exception.GetType().FullName -in @('Microsoft.ActiveDirectory.Management.ADServerDownException', 'System.TimeoutException')) {
            return $true
        }
        $exception = $exception.InnerException
    }
    $false
}

function Invoke-OgwaADCall {
    # Runs a query script and turns failures into OGWA errors: unreachable or failed.
    param(
        [Parameter(Mandatory, Position = 0)][scriptblock]$ADCallScript,
        [switch]$TreatFailureAsUnreachable
    )

    try {
        & $ADCallScript
    }
    catch {
        $text = Get-OgwaErrorText $_
        if ($TreatFailureAsUnreachable -or (Test-OgwaServerDown $_)) { throw ($script:UnreachablePrefix + $text) }
        throw $text
    }
}
