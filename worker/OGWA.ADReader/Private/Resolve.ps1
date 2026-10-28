# Group resolution. A group counts as resolved only when exactly one match is proven.

function Resolve-OgwaGroup {
    # Returns @{ Summary; Domain } for a proven unique match. Otherwise returns $null and
    # records the reason (NotFound, Ambiguous, Inconclusive, Failed) in $Report.resolution.
    param([Parameter(Mandatory)][hashtable]$Context, [Parameter(Mandatory)][object]$Report)

    $lookup = $Context.Request.lookup
    $resolution = $Report.resolution
    $resolution.matchedBy = $lookup.by
    $maxCandidates = $Context.Request.limits.maxAmbiguousCandidates
    $isBuiltinSid = $lookup.by -ceq 'objectSid' -and $lookup.value.StartsWith($script:BuiltinSidPrefix)

    # Narrowest scope first: a named domain, the DN's own domain, or the SID's own domain.
    if ($lookup.domain) {
        if (-not $Context.Domains.ContainsKey($lookup.domain)) {
            throw ($script:InvalidPrefix + "lookup.domain '$($lookup.domain)' is not a domain of this forest")
        }
        $scope = @($lookup.domain)
    }
    elseif ($lookup.by -ceq 'distinguishedName') {
        $owner = Get-OgwaOwningDomain -DistinguishedName $lookup.value -DomainNames $Context.DomainNames
        if (-not $owner) { throw ($script:InvalidPrefix + 'the distinguished name is not in any domain of this forest') }
        $scope = @($owner)
    }
    elseif ($lookup.by -ceq 'objectSid' -and -not $isBuiltinSid) {
        $domainSid = $lookup.value.Substring(0, $lookup.value.LastIndexOf('-'))
        $owner = $null
        $unidentified = [System.Collections.Generic.List[string]]::new()
        foreach ($name in $Context.DomainNames) {
            $state = Get-OgwaDomain -Context $Context -DnsName $name
            if (-not $state.Reachable) { $unidentified.Add($name); continue }
            if ([string](Get-OgwaValue $state.Info 'Sid') -ceq $domainSid) { $owner = $name; break }
        }
        if (-not $owner) {
            if ($unidentified.Count -gt 0) {
                $resolution.status = 'Inconclusive'
                $resolution.unsearchedDomains = @($unidentified)
                $resolution.error = 'no reachable domain owns this SID, and at least one domain could not be contacted'
            }
            else {
                $resolution.status = 'NotFound'
                $resolution.searchedDomains = @($Context.DomainNames)
                $resolution.error = 'no domain of this forest owns this SID'
            }
            return $null
        }
        $scope = @($owner)
    }
    else {
        $scope = @($Context.DomainNames)
    }

    $found = [System.Collections.Generic.List[object]]::new()
    $searched = [System.Collections.Generic.List[string]]::new()
    $unsearched = [System.Collections.Generic.List[string]]::new()
    $errors = [System.Collections.Generic.List[string]]::new()
    $failed = $false
    foreach ($name in $scope) {
        $state = Get-OgwaDomain -Context $Context -DnsName $name
        if (-not $state.Reachable) {
            $unsearched.Add($name)
            $errors.Add("${name}: $($state.Error)")
            continue
        }
        try {
            $hits = @(Invoke-OgwaDirectory -Directory $Context.Directory -Operation 'FindGroups' -ArgumentList @($state.Info, $lookup.by, $lookup.value, ($maxCandidates + 1)))
        }
        catch {
            if (Test-OgwaUnreachableError $_) { Set-OgwaDomainUnreachable -State $state -ErrorRecord $_ } else { $failed = $true }
            $unsearched.Add($name)
            $errors.Add("${name}: " + (Get-OgwaErrorText $_))
            continue
        }
        $searched.Add($name)
        foreach ($hit in $hits) { $found.Add(@{ Summary = $hit; Domain = $name }) }
    }

    $sorted = @(Sort-OgwaByText -Items $found.ToArray() -Key { param($m) Get-OgwaValue $m.Summary 'DistinguishedName' })
    $resolution.searchedDomains = @($searched)
    $resolution.unsearchedDomains = @($unsearched)
    $resolution.candidatesTruncated = $sorted.Count -gt $maxCandidates
    $resolution.candidates = @($sorted | Select-Object -First $maxCandidates | ForEach-Object { New-OgwaGroupRef -Summary $_.Summary -Domain $_.Domain })

    # objectGUID, a DN and a domain SID are unique in the forest, so one match settles it
    # even if another domain was unreachable. Names must be searched everywhere in scope.
    $forestUnique = $lookup.by -cin @('objectGUID', 'distinguishedName') -or ($lookup.by -ceq 'objectSid' -and -not $isBuiltinSid)
    $allSearched = $unsearched.Count -eq 0
    if ($sorted.Count -gt 1) {
        $resolution.status = 'Ambiguous'
        $errors.Insert(0, "$($sorted.Count) groups match; look the group up by objectGUID or objectSid")
    }
    elseif ($sorted.Count -eq 1 -and ($forestUnique -or $allSearched)) {
        $resolution.status = 'Resolved'
    }
    elseif ($sorted.Count -eq 0 -and $allSearched) {
        $resolution.status = 'NotFound'
    }
    elseif ($failed) {
        $resolution.status = 'Failed'
    }
    else {
        $resolution.status = 'Inconclusive'
        $errors.Insert(0, "$($unsearched.Count) domain(s) could not be searched, so the match cannot be proven unique")
    }
    $resolution.error = Join-OgwaErrorText -Messages $errors.ToArray()

    if ($resolution.status -ceq 'Resolved') { return $sorted[0] }
    $null
}
