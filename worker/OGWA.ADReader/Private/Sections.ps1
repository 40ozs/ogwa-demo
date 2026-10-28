# Readers for a resolved group: identity, direct members, nested members,
# primary-group references, parent groups, and protection facts.

function Read-OgwaGroupDetails {
    param([Parameter(Mandatory)][hashtable]$Context, [Parameter(Mandatory)][object]$Report, [Parameter(Mandatory)][hashtable]$Match)

    $resolution = $Report.resolution
    $state = Get-OgwaDomain -Context $Context -DnsName $Match.Domain
    $summaryDn = [string](Get-OgwaValue $Match.Summary 'DistinguishedName')
    $summaryGuid = ConvertTo-OgwaGuidText (Get-OgwaValue $Match.Summary 'ObjectGUID')
    try {
        $group = Invoke-OgwaDirectory -Directory $Context.Directory -Operation 'GetGroup' -ArgumentList @($state.Info, $summaryDn)
    }
    catch {
        if (Test-OgwaUnreachableError $_) {
            Set-OgwaDomainUnreachable -State $state -ErrorRecord $_
            $resolution.status = 'Inconclusive'
        }
        else {
            $resolution.status = 'Failed'
        }
        $resolution.error = Get-OgwaErrorText ('the group was found but could not be read: ' + (Get-OgwaErrorText $_))
        return
    }
    if ($null -eq $group -or (ConvertTo-OgwaGuidText (Get-OgwaValue $group 'ObjectGUID')) -cne $summaryGuid) {
        $resolution.status = 'Failed'
        $resolution.error = 'the group changed between search and read; repeat the lookup'
        return
    }

    $sid = ConvertTo-OgwaSidText (Get-OgwaValue $group 'ObjectSid')
    $adminCount = Get-OgwaValue $group 'AdminCount'
    $protectedFromDeletion = Get-OgwaValue $group 'ProtectedFromAccidentalDeletion'
    $token = Get-OgwaValue $group 'PrimaryGroupToken'
    $Report.group = [ordered]@{
        objectGUID                      = $summaryGuid
        objectSid                       = $sid
        rid                             = Get-OgwaRid -Sid $sid
        domainSid                       = $sid.Substring(0, $sid.LastIndexOf('-'))
        builtinDomain                   = $sid.StartsWith($script:BuiltinSidPrefix)
        distinguishedName               = [string](Get-OgwaValue $group 'DistinguishedName')
        samAccountName                  = [string](Get-OgwaValue $group 'SamAccountName')
        name                            = [string](Get-OgwaValue $group 'Name')
        domain                          = $Match.Domain
        groupScope                      = [string](Get-OgwaValue $group 'GroupScope')
        groupCategory                   = [string](Get-OgwaValue $group 'GroupCategory')
        adminCount                      = if ($null -eq $adminCount) { $null } else { [int]$adminCount }
        isCriticalSystemObject          = [bool](Get-OgwaValue $group 'IsCriticalSystemObject')
        # $null means the security descriptor could not be read: protection is then undetermined.
        protectedFromAccidentalDeletion = if ($null -eq $protectedFromDeletion) { $null } else { [bool]$protectedFromDeletion }
        primaryGroupToken               = if ($null -eq $token) { $null } else { [long]$token }
        whenCreated                     = ConvertTo-OgwaUtcText (Get-OgwaValue $group 'WhenCreated')
        whenChanged                     = ConvertTo-OgwaUtcText (Get-OgwaValue $group 'WhenChanged')
    }

    $include = $Context.Request.include
    $memberDns = [string[]]@(Get-OgwaValue $group 'Member' | Where-Object { $_ } | ForEach-Object { [string]$_ })
    [Array]::Sort($memberDns, [StringComparer]::OrdinalIgnoreCase)

    $memberGroups = @()
    if ($include.directMembers) {
        $memberGroups = @(Read-OgwaDirectMembers -Context $Context -Report $Report -MemberDns $memberDns)
    }
    else {
        $Report.directMembers.status = 'NotRequested'
    }
    if ($include.nestedMembers) {
        Read-OgwaNestedMembers -Context $Context -Report $Report -MemberGroups $memberGroups
    }
    else {
        $Report.nestedMembers.status = 'NotRequested'
    }
    if ($include.primaryGroupReferences) {
        Read-OgwaPrimaryGroupReferences -Context $Context -Report $Report
    }
    else {
        $Report.primaryGroupReferences.status = 'NotRequested'
    }
    if ($include.memberOf) {
        Read-OgwaParentGroups -Context $Context -Report $Report
    }
    else {
        $Report.memberOf.status = 'NotRequested'
    }
    Set-OgwaProtectionFacts -Report $Report
}

function Get-OgwaMemberClassification {
    # Looks up member DNs in their own domains, in batches. Returns the classified members
    # and how many could not be resolved (unknown domain, unreachable domain, or no object).
    param([Parameter(Mandatory)][hashtable]$Context, [AllowEmptyCollection()][string[]]$DistinguishedNames)

    $result = @{
        Members    = [System.Collections.Generic.List[object]]::new()
        Unresolved = 0
        Errors     = [System.Collections.Generic.List[string]]::new()
    }
    $byDomain = [ordered]@{}
    foreach ($dn in $DistinguishedNames) {
        $owner = Get-OgwaOwningDomain -DistinguishedName $dn -DomainNames $Context.DomainNames
        if (-not $owner) {
            $result.Unresolved++
            continue
        }
        if (-not $byDomain.Contains($owner)) { $byDomain[$owner] = [System.Collections.Generic.List[string]]::new() }
        $byDomain[$owner].Add($dn)
    }

    foreach ($domainName in @($byDomain.Keys)) {
        $pending = $byDomain[$domainName]
        $state = Get-OgwaDomain -Context $Context -DnsName $domainName
        $reported = $false
        for ($offset = 0; $offset -lt $pending.Count; $offset += $script:DnBatchSize) {
            [string[]]$batch = $pending.GetRange($offset, [Math]::Min($script:DnBatchSize, $pending.Count - $offset)).ToArray()
            if (-not $state.Reachable) {
                $result.Unresolved += $batch.Count
                if (-not $reported) { $result.Errors.Add("${domainName}: $($state.Error)"); $reported = $true }
                continue
            }
            try {
                $objects = @(Invoke-OgwaDirectory -Directory $Context.Directory -Operation 'GetObjectsByDn' -ArgumentList @($state.Info, $batch))
            }
            catch {
                if (Test-OgwaUnreachableError $_) { Set-OgwaDomainUnreachable -State $state -ErrorRecord $_ }
                $result.Errors.Add("${domainName}: " + (Get-OgwaErrorText $_))
                $reported = $true
                $result.Unresolved += $batch.Count
                continue
            }
            $index = @{}
            foreach ($object in $objects) { $index[[string](Get-OgwaValue $object 'DistinguishedName')] = $object }
            foreach ($dn in $batch) {
                $object = $index[$dn]
                if ($null -eq $object) {
                    $result.Unresolved++
                    continue
                }
                $result.Members.Add(@{
                        Dn    = $dn
                        Class = ConvertTo-OgwaMemberClass ([string](Get-OgwaValue $object 'ObjectClass'))
                        Ref   = New-OgwaGroupRef -Summary $object -Domain $domainName
                    })
            }
        }
    }
    $result
}

function Read-OgwaDirectMembers {
    # Counts the group's own member values and classifies them. Returns the member groups.
    param([Parameter(Mandatory)][hashtable]$Context, [Parameter(Mandatory)][object]$Report, [AllowEmptyCollection()][string[]]$MemberDns)

    $section = $Report.directMembers
    $limit = $Context.Request.limits.maxDirectMembers
    $truncated = $MemberDns.Count -gt $limit
    $toClassify = if ($truncated) { $MemberDns[0..($limit - 1)] } else { $MemberDns }
    $classified = Get-OgwaMemberClassification -Context $Context -DistinguishedNames $toClassify

    $section.count = $MemberDns.Count
    foreach ($member in $classified.Members) { $section.byClass[$member.Class]++ }
    $groups = @(Sort-OgwaByText -Items @($classified.Members | Where-Object { $_.Class -ceq 'group' } | ForEach-Object { $_.Ref }) -Key { param($r) $r.distinguishedName })
    $section.memberGroups = $groups
    $section.unresolved = $classified.Unresolved

    $errors = @($classified.Errors)
    if ($truncated) { $errors = @("classified the first $limit of $($MemberDns.Count) members (maxDirectMembers)") + $errors }
    $section.status = Get-OgwaSectionStatus -Truncated $truncated -Partial ($classified.Unresolved -gt 0 -or $classified.Errors.Count -gt 0)
    $section.error = Join-OgwaErrorText -Messages $errors
    $groups
}

function Read-OgwaNestedMembers {
    # Breadth-first expansion of member groups. Counts the principals reached through them,
    # plus objects that use a nested group as their primary group. Bounded by the limits.
    param([Parameter(Mandatory)][hashtable]$Context, [Parameter(Mandatory)][object]$Report, [AllowEmptyCollection()][object[]]$MemberGroups)

    $section = $Report.nestedMembers
    $limits = $Context.Request.limits
    $rootDn = $Report.group.distinguishedName
    $visited = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    [void]$visited.Add($rootDn)
    $principals = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $queue = [System.Collections.Generic.Queue[object]]::new()
    foreach ($ref in $MemberGroups) {
        if ($visited.Add($ref.distinguishedName)) { $queue.Enqueue(@{ Ref = $ref; Depth = 1; Ancestors = @($rootDn) }) }
    }

    # Nesting cannot be complete if the direct members were not.
    $truncated = $Report.directMembers.status -ceq 'Truncated'
    $partial = $Report.directMembers.status -cin @('Partial', 'Failed')
    $errors = [System.Collections.Generic.List[string]]::new()
    $traversed = 0
    $maxDepth = 0
    $primaryReferences = 0
    $primaryLowerBound = $false
    $cycle = $false
    $unexpanded = 0

    while ($queue.Count -gt 0) {
        $item = $queue.Dequeue()
        if ($traversed -ge $limits.maxNestedGroups -or $item.Depth -gt $limits.maxNestingDepth) {
            # Breadth-first: every queued group is at least this deep, so stop here.
            $truncated = $true
            $unexpanded += 1 + $queue.Count
            $errors.Add("stopped after $traversed nested groups at depth $($item.Depth - 1) (maxNestedGroups $($limits.maxNestedGroups), maxNestingDepth $($limits.maxNestingDepth))")
            break
        }
        $traversed++
        if ($item.Depth -gt $maxDepth) { $maxDepth = $item.Depth }
        $ref = $item.Ref
        $state = Get-OgwaDomain -Context $Context -DnsName $ref.domain
        if ($null -eq $state -or -not $state.Reachable) {
            $partial = $true
            $unexpanded++
            $errors.Add("$($ref.domain): domain unreachable")
            continue
        }
        try {
            $group = Invoke-OgwaDirectory -Directory $Context.Directory -Operation 'GetGroup' -ArgumentList @($state.Info, $ref.distinguishedName)
        }
        catch {
            if (Test-OgwaUnreachableError $_) { Set-OgwaDomainUnreachable -State $state -ErrorRecord $_ }
            $partial = $true
            $unexpanded++
            $errors.Add("$($ref.domain): " + (Get-OgwaErrorText $_))
            continue
        }
        if ($null -eq $group) {
            $partial = $true
            $unexpanded++
            continue
        }

        $memberDns = [string[]]@(Get-OgwaValue $group 'Member' | Where-Object { $_ } | ForEach-Object { [string]$_ })
        [Array]::Sort($memberDns, [StringComparer]::OrdinalIgnoreCase)
        if ($memberDns.Count -gt $limits.maxDirectMembers) {
            $truncated = $true
            $memberDns = $memberDns[0..($limits.maxDirectMembers - 1)]
        }
        $classified = Get-OgwaMemberClassification -Context $Context -DistinguishedNames $memberDns
        $unexpanded += $classified.Unresolved
        if ($classified.Unresolved -gt 0 -or $classified.Errors.Count -gt 0) { $partial = $true }
        foreach ($message in $classified.Errors) { $errors.Add($message) }

        $path = @($item.Ancestors) + @($ref.distinguishedName)
        foreach ($member in $classified.Members) {
            if ($member.Class -cne 'group') {
                [void]$principals.Add($member.Dn)
            }
            elseif ($path -contains $member.Dn) {
                $cycle = $true
            }
            elseif ($visited.Add($member.Dn)) {
                $queue.Enqueue(@{ Ref = $member.Ref; Depth = $item.Depth + 1; Ancestors = $path })
            }
        }

        $rid = Get-OgwaRid -Sid $ref.objectSid
        if ($null -eq $rid) {
            $partial = $true
            continue
        }
        try {
            $count = [int](Invoke-OgwaDirectory -Directory $Context.Directory -Operation 'CountPrimaryGroupReferences' -ArgumentList @($state.Info, $rid, ($limits.maxPrimaryGroupReferences + 1)))
            if ($count -gt $limits.maxPrimaryGroupReferences) {
                $count = $limits.maxPrimaryGroupReferences
                $primaryLowerBound = $true
            }
            $primaryReferences += $count
        }
        catch {
            if (Test-OgwaUnreachableError $_) { Set-OgwaDomainUnreachable -State $state -ErrorRecord $_ }
            $partial = $true
            $errors.Add("$($ref.domain): " + (Get-OgwaErrorText $_))
        }
    }

    $section.groupsTraversed = $traversed
    $section.maxDepthObserved = $maxDepth
    $section.principalCount = $principals.Count + $primaryReferences
    $section.principalCountIsLowerBound = $truncated -or $partial -or $primaryLowerBound
    $section.cycleDetected = $cycle
    $section.unexpandedReferences = $unexpanded
    $section.status = Get-OgwaSectionStatus -Truncated $truncated -Partial $partial
    $section.error = Join-OgwaErrorText -Messages $errors.ToArray()
}

function Read-OgwaPrimaryGroupReferences {
    # Users and computers whose primaryGroupID is this group's RID are members that the
    # member attribute does not list. Only the group's own domain can hold them.
    param([Parameter(Mandatory)][hashtable]$Context, [Parameter(Mandatory)][object]$Report)

    $section = $Report.primaryGroupReferences
    $group = $Report.group
    $limit = $Context.Request.limits.maxPrimaryGroupReferences
    $section.primaryGroupToken = $group.rid
    $section.searchedDomain = $group.domain
    $state = Get-OgwaDomain -Context $Context -DnsName $group.domain
    try {
        $count = [int](Invoke-OgwaDirectory -Directory $Context.Directory -Operation 'CountPrimaryGroupReferences' -ArgumentList @($state.Info, $group.rid, ($limit + 1)))
    }
    catch {
        if (Test-OgwaUnreachableError $_) { Set-OgwaDomainUnreachable -State $state -ErrorRecord $_ }
        $section.status = 'Failed'
        $section.error = Get-OgwaErrorText $_
        return
    }
    if ($count -gt $limit) {
        $section.count = $limit
        $section.countIsLowerBound = $true
        $section.status = 'Truncated'
        $section.error = "stopped counting at maxPrimaryGroupReferences ($limit)"
    }
    else {
        $section.count = $count
        $section.status = 'Complete'
    }
}

function Read-OgwaParentGroups {
    # Groups that list this group as a member. Parents can live in any forest domain
    # (universal and domain-local groups), so every domain is asked.
    param([Parameter(Mandatory)][hashtable]$Context, [Parameter(Mandatory)][object]$Report)

    $section = $Report.memberOf
    $limit = $Context.Request.limits.maxParentGroups
    $groupDn = $Report.group.distinguishedName
    $parents = [System.Collections.Generic.List[object]]::new()
    $searched = [System.Collections.Generic.List[string]]::new()
    $unsearched = [System.Collections.Generic.List[string]]::new()
    $errors = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $Context.DomainNames) {
        $state = Get-OgwaDomain -Context $Context -DnsName $name
        if (-not $state.Reachable) {
            $unsearched.Add($name)
            $errors.Add("${name}: $($state.Error)")
            continue
        }
        try {
            $found = @(Invoke-OgwaDirectory -Directory $Context.Directory -Operation 'FindParentGroups' -ArgumentList @($state.Info, $groupDn, ($limit + 1)))
        }
        catch {
            if (Test-OgwaUnreachableError $_) { Set-OgwaDomainUnreachable -State $state -ErrorRecord $_ }
            $unsearched.Add($name)
            $errors.Add("${name}: " + (Get-OgwaErrorText $_))
            continue
        }
        $searched.Add($name)
        foreach ($parent in $found) { $parents.Add((New-OgwaGroupRef -Summary $parent -Domain $name)) }
    }

    $sorted = @(Sort-OgwaByText -Items $parents.ToArray() -Key { param($r) $r.distinguishedName })
    $truncated = $sorted.Count -gt $limit
    if ($truncated) {
        $sorted = @($sorted[0..($limit - 1)])
        $errors.Insert(0, "stopped at maxParentGroups ($limit)")
    }
    $section.parents = $sorted
    $section.count = $sorted.Count
    $section.countIsLowerBound = $truncated -or $unsearched.Count -gt 0
    $section.searchedDomains = @($searched)
    $section.unsearchedDomains = @($unsearched)
    $section.status = if ($searched.Count -eq 0) { 'Failed' } else { Get-OgwaSectionStatus -Truncated $truncated -Partial ($unsearched.Count -gt 0) }
    $section.error = Join-OgwaErrorText -Messages $errors.ToArray()
}

function Set-OgwaProtectionFacts {
    # Supporting indicators only. OGWA applies its own protection policy to these facts;
    # anything this worker cannot read makes protection Undetermined, never "not protected".
    param([Parameter(Mandatory)][object]$Report)

    $group = $Report.group
    $section = $Report.protection
    $indicators = [System.Collections.Generic.List[string]]::new()
    $gaps = [System.Collections.Generic.List[string]]::new()

    if ($group.builtinDomain) { $indicators.Add('BuiltinDomainSid') }
    if ($group.rid -lt $script:FirstOrdinaryRid) { $indicators.Add("WellKnownRid:$($group.rid)") }
    if ($null -ne $group.adminCount -and $group.adminCount -ne 0) { $indicators.Add('AdminCount') }
    if ($group.isCriticalSystemObject) { $indicators.Add('CriticalSystemObject') }
    if ($group.protectedFromAccidentalDeletion -eq $true) { $indicators.Add('ProtectedFromAccidentalDeletion') }
    elseif ($null -eq $group.protectedFromAccidentalDeletion) { $gaps.Add('ProtectedFromAccidentalDeletion could not be read') }
    foreach ($parent in @($Report.memberOf.parents)) {
        if (Test-OgwaWellKnownSid -Sid $parent.objectSid) { $indicators.Add("NestedInWellKnownGroup:$($parent.objectSid)") }
    }
    if ($Report.memberOf.status -cne 'Complete') { $gaps.Add("parent groups were not fully read (memberOf $($Report.memberOf.status))") }

    $section.indicators = @($indicators)
    $section.status = if ($gaps.Count -gt 0) { 'Undetermined' } else { 'Determined' }
    $section.error = Join-OgwaErrorText -Messages $gaps.ToArray()
}
