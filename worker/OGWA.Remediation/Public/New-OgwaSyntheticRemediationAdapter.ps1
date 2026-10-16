function New-OgwaSyntheticRemediationAdapter {
    <#
    .SYNOPSIS
        Creates the in-memory synthetic adapter: the only adapter in this build.

    .DESCRIPTION
        The adapter is data: a copy of the synthetic world given here, and a log of every
        lookup and change. The remediation commands accept it only because it carries this
        module's private token. Every identity must be synthetic: domains under
        synthetic.example (reserved, RFC 2606) and Okta ids that start 0oaSYNTH / 00gSYNTH.
        Anything else is refused, so the adapter cannot even describe a real object.

        A group is a hashtable with ObjectGuid, Domain, Sid, DistinguishedName,
        SamAccountName, AdminCount, ProtectedFromAccidentalDeletion (each $true, $false, or
        $null for "could not be read"), IsCriticalSystemObject, MemberCount and
        MemberOfCount. An Okta assignment has AppId, GroupId and GroupType (APP_GROUP,
        OKTA_GROUP or BUILT_IN).

    .EXAMPLE
        $adapter = New-OgwaSyntheticRemediationAdapter -Groups @($group) -OrganizationalUnits @($ou)
        Remove-OgwaADGroup @target -Adapter $adapter -WhatIf
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [object[]]$Groups = @(),
        [string[]]$OrganizationalUnits = @(),
        [object[]]$OktaAssignments = @()
    )

    $groupKeys = @('ObjectGuid', 'Domain', 'Sid', 'DistinguishedName', 'SamAccountName', 'AdminCount',
        'ProtectedFromAccidentalDeletion', 'IsCriticalSystemObject', 'MemberCount', 'MemberOfCount')
    $world = @{
        Groups              = New-Object System.Collections.Generic.List[object]
        OrganizationalUnits = New-Object System.Collections.Generic.List[string]
        OktaAssignments     = New-Object System.Collections.Generic.List[object]
    }
    foreach ($group in $Groups) {
        if (-not ($group -is [System.Collections.IDictionary])) { throw 'each synthetic group is a hashtable' }
        foreach ($key in $groupKeys) {
            if (-not $group.Contains($key)) { throw "a synthetic group needs $key" }
        }
        if (-not (Test-OgwaSyntheticDomain -Domain $group.Domain) -or $group.ObjectGuid -cnotmatch $script:GuidPattern -or
            $group.Sid -cnotmatch $script:SidPattern -or
            -not (Test-OgwaDnInDomain -DistinguishedName $group.DistinguishedName -DomainDn (ConvertTo-OgwaDomainDn -DnsName $group.Domain))) {
            throw 'only synthetic groups (a lowercase GUID, a SID, and a DN inside a *.synthetic.example domain) are accepted'
        }
        $world.Groups.Add(@{
                ObjectGuid                      = [string]$group.ObjectGuid
                Domain                          = [string]$group.Domain
                Sid                             = [string]$group.Sid
                DistinguishedName               = [string]$group.DistinguishedName
                SamAccountName                  = [string]$group.SamAccountName
                AdminCount                      = $group.AdminCount
                ProtectedFromAccidentalDeletion = $group.ProtectedFromAccidentalDeletion
                IsCriticalSystemObject          = [bool]$group.IsCriticalSystemObject
                MemberCount                     = if ($null -eq $group.MemberCount) { $null } else { [int]$group.MemberCount }
                MemberOfCount                   = if ($null -eq $group.MemberOfCount) { $null } else { [int]$group.MemberOfCount }
            })
    }
    foreach ($ou in $OrganizationalUnits) {
        if (-not $ou -or -not $ou.StartsWith('OU=', [StringComparison]::OrdinalIgnoreCase) -or
            -not $ou.EndsWith(',DC=synthetic,DC=example', [StringComparison]::OrdinalIgnoreCase)) {
            throw 'only synthetic organizational units (OU=...,DC=synthetic,DC=example) are accepted'
        }
        $world.OrganizationalUnits.Add($ou)
    }
    foreach ($assignment in $OktaAssignments) {
        if (-not ($assignment -is [System.Collections.IDictionary]) -or
            -not ([string]$assignment.AppId).StartsWith($script:SyntheticOktaAppPrefix) -or
            -not ([string]$assignment.GroupId).StartsWith($script:SyntheticOktaGroupPrefix) -or
            @('APP_GROUP', 'OKTA_GROUP', 'BUILT_IN') -cnotcontains $assignment.GroupType) {
            throw 'only synthetic Okta assignments (AppId 0oaSYNTH..., GroupId 00gSYNTH..., a known GroupType) are accepted'
        }
        $world.OktaAssignments.Add(@{ AppId = [string]$assignment.AppId; GroupId = [string]$assignment.GroupId
                GroupType = [string]$assignment.GroupType })
    }
    @{
        Kind  = 'Synthetic'
        Token = $script:SyntheticAdapterToken
        World = $world
        Log   = New-Object System.Collections.Generic.List[string]
    }
}
