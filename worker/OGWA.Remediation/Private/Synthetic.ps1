# The synthetic adapter's internals. The adapter is data (an in-memory world and a log);
# the only code that reads or changes it is in this file. There is no other adapter.

function Test-OgwaSyntheticAdapter {
    # True only for an adapter made by New-OgwaSyntheticRemediationAdapter in this module.
    param([AllowNull()][object]$Adapter)

    ($Adapter -is [System.Collections.IDictionary]) -and $Adapter.Contains('Token') -and
        [object]::ReferenceEquals($Adapter['Token'], $script:SyntheticAdapterToken)
}

function Assert-OgwaSyntheticAdapter {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Result, [AllowNull()][object]$Adapter)

    if (-not (Test-OgwaSyntheticAdapter -Adapter $Adapter)) {
        Stop-OgwaRemediation -Result $Result -Code 'ADAPTER_SYNTHETIC' -Reason 'NO_PRODUCTION_ADAPTER' -Detail (
            'this build has no production adapter; only the in-memory adapter made by ' +
            'New-OgwaSyntheticRemediationAdapter is accepted, and nothing outside it can change')
        return $false
    }
    Add-OgwaCheck -Result $Result -Code 'ADAPTER_SYNTHETIC' -Passed $true -Detail 'the in-memory synthetic adapter'
    $true
}

function Find-OgwaSyntheticGroup {
    # Every group with this objectGUID in this domain (0, 1, or more).
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Adapter, [string]$ObjectGuid, [string]$Domain)

    $Adapter.Log.Add("FindGroup:${Domain}:$ObjectGuid")
    , @($Adapter.World.Groups | Where-Object { $_.ObjectGuid -ceq $ObjectGuid -and $_.Domain -ceq $Domain })
}

function Test-OgwaSyntheticOrganizationalUnit {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Adapter, [string]$DistinguishedName)

    $Adapter.Log.Add("FindOU:$DistinguishedName")
    @($Adapter.World.OrganizationalUnits | Where-Object { $_.Equals($DistinguishedName, [StringComparison]::OrdinalIgnoreCase) }).Count -eq 1
}

function Find-OgwaSyntheticAssignment {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Adapter, [string]$AppId, [string]$GroupId)

    $Adapter.Log.Add("FindAssignment:${AppId}:$GroupId")
    , @($Adapter.World.OktaAssignments | Where-Object { $_.AppId -ceq $AppId -and $_.GroupId -ceq $GroupId })
}

function Invoke-OgwaSyntheticChange {
    # Applies one change to the synthetic adapter's in-memory world, and to nothing else.
    # Reached only after ShouldProcess agreed; refuses any adapter this module did not make.
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Adapter,
        [Parameter(Mandatory)][ValidateSet('RemoveAssignment', 'MoveGroup', 'RemoveGroup')][string]$Change,
        [Parameter(Mandatory)][hashtable]$Arguments
    )

    if (-not (Test-OgwaSyntheticAdapter -Adapter $Adapter)) {
        throw 'OGWA changes nothing through an adapter it did not make; this build has no production adapter'
    }
    $world = $Adapter.World
    $Adapter.Log.Add("Change:$Change")
    switch ($Change) {
        'RemoveAssignment' {
            $found = @($world.OktaAssignments | Where-Object { $_.AppId -ceq $Arguments.AppId -and $_.GroupId -ceq $Arguments.GroupId })
            if ($found.Count -ne 1) { throw 'the synthetic assignment is gone' }
            [void]$world.OktaAssignments.Remove($found[0])
        }
        'MoveGroup' {
            $found = @($world.Groups | Where-Object { $_.ObjectGuid -ceq $Arguments.ObjectGuid -and $_.Domain -ceq $Arguments.Domain })
            if ($found.Count -ne 1) { throw 'the synthetic group is gone' }
            $found[0].DistinguishedName = $Arguments.DistinguishedName
        }
        'RemoveGroup' {
            $found = @($world.Groups | Where-Object { $_.ObjectGuid -ceq $Arguments.ObjectGuid -and $_.Domain -ceq $Arguments.Domain })
            if ($found.Count -ne 1) { throw 'the synthetic group is gone' }
            [void]$world.Groups.Remove($found[0])
        }
    }
}

function Resolve-OgwaADTarget {
    # The one synthetic group the request names, after the adapter, synthetic-identity,
    # resolution, identity and protection checks; $null (with the reason recorded) otherwise.
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Result,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Values,
        [AllowNull()][object]$Adapter
    )

    if (-not (Assert-OgwaSyntheticAdapter -Result $Result -Adapter $Adapter)) { return $null }
    if (-not (Test-OgwaSyntheticDomain -Domain $Values.domain)) {
        Stop-OgwaRemediation -Result $Result -Code 'TARGET_SYNTHETIC' -Reason 'NON_SYNTHETIC_TARGET' -Detail (
            "$($Values.domain) is not a synthetic domain; the synthetic adapter serves *.$($script:SyntheticDomainSuffix) only")
        return $null
    }
    Add-OgwaCheck -Result $Result -Code 'TARGET_SYNTHETIC' -Passed $true -Detail 'a synthetic domain'

    $groups = Find-OgwaSyntheticGroup -Adapter $Adapter -ObjectGuid $Values.objectGuid -Domain $Values.domain
    if ($groups.Count -eq 0) {
        Stop-OgwaRemediation -Result $Result -Code 'TARGET_RESOLVED' -Reason 'TARGET_NOT_FOUND' -Detail 'no group has this objectGUID in this domain'
        return $null
    }
    if ($groups.Count -gt 1) {
        Stop-OgwaRemediation -Result $Result -Code 'TARGET_RESOLVED' -Reason 'TARGET_AMBIGUOUS' -Detail 'more than one object answers to this objectGUID'
        return $null
    }
    $group = $groups[0]
    Add-OgwaCheck -Result $Result -Code 'TARGET_RESOLVED' -Passed $true -Detail 'exactly one group, by objectGUID'

    $changed = @()
    if ($group.Sid -cne $Values.expectedSid) { $changed += 'objectSid' }
    if (-not $group.DistinguishedName.Equals($Values.expectedDistinguishedName, [StringComparison]::OrdinalIgnoreCase)) {
        $changed += 'distinguishedName'
    }
    if ($changed.Count -gt 0) {
        Stop-OgwaRemediation -Result $Result -Code 'IDENTITY_MATCHES' -Reason 'TARGET_IDENTITY_CHANGED' -Detail (
            "the group's $($changed -join ' and ') no longer match what OGWA approved; review it again")
        return $null
    }
    Add-OgwaCheck -Result $Result -Code 'IDENTITY_MATCHES' -Passed $true -Detail 'objectSid and distinguishedName match'

    if ($null -eq $group.AdminCount -or $null -eq $group.ProtectedFromAccidentalDeletion) {
        Stop-OgwaRemediation -Result $Result -Code 'NOT_PROTECTED' -Reason 'PROTECTION_UNDETERMINED' -Detail (
            'adminCount or ProtectedFromAccidentalDeletion could not be read; unknown protection blocks and cannot be overridden')
        return $null
    }
    $protection = @()
    if ($group.AdminCount) { $protection += 'adminCount is set' }
    if ($group.ProtectedFromAccidentalDeletion) { $protection += 'ProtectedFromAccidentalDeletion' }
    if ($group.IsCriticalSystemObject) { $protection += 'a critical system object' }
    if (Test-OgwaWellKnownSid -Sid $group.Sid) { $protection += 'a well-known SID' }
    if ($protection.Count -gt 0) {
        Stop-OgwaRemediation -Result $Result -Code 'NOT_PROTECTED' -Reason 'PROTECTED_TARGET' -Detail (
            'protected: ' + ($protection -join '; ') + '. Protection cannot be overridden.')
        return $null
    }
    Add-OgwaCheck -Result $Result -Code 'NOT_PROTECTED' -Passed $true -Detail 'no protection indicator'
    $group
}

function Test-OgwaGroupIsEmpty {
    # Members and parent groups both block every AD remediation (D36, AD_NESTED_MEMBERSHIP).
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Result, [Parameter(Mandatory)][object]$Group)

    if ($Group.MemberCount -isnot [int] -or $Group.MemberCount -ne 0) {
        Stop-OgwaRemediation -Result $Result -Code 'NO_MEMBERS' -Reason 'HAS_MEMBERS' -Detail (
            'the group has members, or its member count is unknown')
        return $false
    }
    Add-OgwaCheck -Result $Result -Code 'NO_MEMBERS' -Passed $true -Detail 'no direct members'
    if ($Group.MemberOfCount -isnot [int] -or $Group.MemberOfCount -ne 0) {
        Stop-OgwaRemediation -Result $Result -Code 'NO_PARENT_GROUPS' -Reason 'HAS_PARENT_GROUPS' -Detail (
            'the group is a member of other groups, or that is unknown')
        return $false
    }
    Add-OgwaCheck -Result $Result -Code 'NO_PARENT_GROUPS' -Passed $true -Detail 'not a member of any group'
    $true
}
