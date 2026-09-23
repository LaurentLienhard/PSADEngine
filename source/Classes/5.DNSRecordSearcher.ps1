class DNSRecordSearcher {
    [string]$SearchTerm
    [ValidateSet('Static', 'Dynamic', 'All')]
    [string]$RecordType = 'All'
    [ValidateSet('A', 'AAAA', 'CNAME', 'PTR', 'TXT', 'MX', 'SRV', 'SOA', 'NS', 'All')]
    [string[]]$RRType = @('All')
    [string[]]$IPScope
    [string]$ZoneName
    [string]$Server
    [PSCredential]$Credential

    hidden [System.Collections.Generic.List[hashtable]]$ParsedSubnets
    hidden [System.Net.CimSession]$CimSession

    DNSRecordSearcher() {
        $this.ParsedSubnets = [System.Collections.Generic.List[hashtable]]::new()
    }

    DNSRecordSearcher([string]$SearchTerm, [string]$RecordType, [string[]]$RRType, [string[]]$IPScope,
                      [string]$ZoneName, [string]$Server, [PSCredential]$Credential) {
        $this.SearchTerm = $SearchTerm
        $this.RecordType = $RecordType
        $this.RRType = $RRType
        $this.IPScope = $IPScope
        $this.ZoneName = $ZoneName
        $this.Server = $Server
        $this.Credential = $Credential
        $this.ParsedSubnets = [System.Collections.Generic.List[hashtable]]::new()
    }

    [void] ParseCIDRSubnets() {
        if ($null -eq $this.IPScope -or $this.IPScope.Count -eq 0) {
            return
        }

        $this.ParsedSubnets.Clear()

        foreach ($scopeItem in $this.IPScope) {
            if ([string]::IsNullOrWhiteSpace($scopeItem)) { continue }
            $cleanScope = $scopeItem.Trim()

            if ($cleanScope.Contains('/')) {
                try {
                    $parts = $cleanScope.Split('/')
                    $networkIP = [System.Net.IPAddress]::Parse($parts[0])
                    $cidr = [int]$parts[1]
                    $netBytes = $networkIP.GetAddressBytes()

                    $maskBytes = [byte[]]::new($netBytes.Length)
                    $fullBytes = [math]::DivRem($cidr, 8, [ref]$restBits)
                    for ($i = 0; $i -lt $fullBytes; $i++) { $maskBytes[$i] = 0xff }
                    if ($restBits -gt 0) { $maskBytes[$fullBytes] = [byte](0xff -shl (8 - $restBits)) }

                    $this.ParsedSubnets.Add(@{
                        Type         = 'CIDR'
                        NetworkBytes = $netBytes
                        MaskBytes    = $maskBytes
                        Original     = $cleanScope
                    })
                }
                catch {
                    Write-Warning -Message "Failed to parse CIDR scope '$cleanScope'. Falling back to prefix string matching."
                    $this.ParsedSubnets.Add(@{
                        Type     = 'Prefix'
                        Prefix   = $cleanScope.Split('/')[0]
                        Original = $cleanScope
                    })
                }
            }
            else {
                $this.ParsedSubnets.Add(@{
                    Type     = 'Prefix'
                    Prefix   = $cleanScope
                    Original = $cleanScope
                })
            }
        }
    }

    [bool] EvaluateIPScope([string]$EvalIpAddress) {
        if ($this.ParsedSubnets.Count -eq 0) {
            return $true
        }

        if ([string]::IsNullOrEmpty($EvalIpAddress)) {
            return $false
        }

        foreach ($subnetObj in $this.ParsedSubnets) {
            if ($subnetObj.Type -eq 'CIDR') {
                try {
                    $targetIP = [System.Net.IPAddress]::Parse($EvalIpAddress)
                    $targetBytes = $targetIP.GetAddressBytes()

                    if ($targetBytes.Length -eq $subnetObj.NetworkBytes.Length) {
                        $byteMatch = $true
                        for ($i = 0; $i -lt $targetBytes.Length; $i++) {
                            if (($targetBytes[$i] -band $subnetObj.MaskBytes[$i]) -ne ($subnetObj.NetworkBytes[$i] -band $subnetObj.MaskBytes[$i])) {
                                $byteMatch = $false
                                break
                            }
                        }
                        if ($byteMatch) {
                            return $true
                        }
                    }
                }
                catch {
                    # Ignore parsing errors on non-standard IP formats
                }
            }
            elseif ($subnetObj.Type -eq 'Prefix') {
                if ($EvalIpAddress.StartsWith($subnetObj.Prefix)) {
                    return $true
                }
            }
        }

        return $false
    }

    [void] InitializeZoneName() {
        if ([string]::IsNullOrWhiteSpace($this.ZoneName)) {
            try {
                $this.ZoneName = (Get-ADDomain).DNSRoot
                Write-Verbose -Message "No ZoneName provided. Defaulted to AD Domain Root: $($this.ZoneName)"
            }
            catch [System.Exception] {
                $rootCause = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
                Write-Error -Message "Failed to auto-detect Active Directory Domain Root Zone: $rootCause" -ErrorAction Stop
            }
        }
    }

    [void] EstablishCimSession() {
        if ($null -ne $this.Credential) {
            $targetComputer = if (-not [string]::IsNullOrWhiteSpace($this.Server)) { $this.Server } else { 'localhost' }
            Write-Verbose -Message "Establishing authenticated CIM Session to [$targetComputer] with user [$($this.Credential.UserName)]..."

            $cimSessionParams = @{
                ComputerName = $targetComputer
                Credential   = $this.Credential
                ErrorAction  = 'Stop'
            }
            $this.CimSession = New-CimSession @cimSessionParams
        }
    }

    [void] DisposeCimSession() {
        if ($null -ne $this.CimSession) {
            Write-Verbose -Message "Disposing active CIM session..."
            Remove-CimSession -CimSession $this.CimSession -ErrorAction SilentlyContinue
        }
    }

    [object[]] GetDNSRecords() {
        $getDnsParams = @{
            ZoneName    = $this.ZoneName
            ErrorAction = 'Stop'
        }

        if ($null -ne $this.CimSession) {
            $getDnsParams['CimSession'] = $this.CimSession
        }
        elseif (-not [string]::IsNullOrWhiteSpace($this.Server)) {
            $getDnsParams['ComputerName'] = $this.Server
        }

        Write-Verbose -Message "Fetching raw DNS records from zone [$($this.ZoneName)]..."
        return Get-DnsServerResourceRecord @getDnsParams
    }

    [string] ExtractTargetData([object]$Record) {
        return switch ($Record.RecordType) {
            'A'     { [string]$Record.RecordData.IPv4Address.IPAddressToString }
            'AAAA'  { [string]$Record.RecordData.IPv6Address.IPAddressToString }
            'CNAME' { [string]$Record.RecordData.HostNameAlias }
            'PTR'   { [string]$Record.RecordData.PtrDomainName }
            'TXT'   { [string]($Record.RecordData.DescriptiveText -join ' ') }
            'MX'    { [string]$Record.RecordData.MailExchange }
            'SRV'   { [string]"$($Record.RecordData.DomainName):$($Record.RecordData.Port)" }
            Default { [string]$Record.RecordData.ToString() }
        }
    }

    [string] ExtractEvalIpAddress([object]$Record) {
        if ($Record.RecordType -eq 'A') {
            return [string]$Record.RecordData.IPv4Address.IPAddressToString
        }
        elseif ($Record.RecordType -eq 'AAAA') {
            return [string]$Record.RecordData.IPv6Address.IPAddressToString
        }
        return $null
    }

    [PSCustomObject[]] Search() {
        $ErrorActionPreference = 'Stop'
        Write-Verbose -Message "Initializing DNS Search Session. NatureFilter: [$($this.RecordType)], RRTypeFilter: [$($this.RRType -join ', ')], IPScopeFilter: [$($this.IPScope -join ', ')]"

        try {
            $this.InitializeZoneName()
            $this.ParseCIDRSubnets()
            $this.EstablishCimSession()

            $rawRecords = $this.GetDNSRecords()
            Write-Verbose -Message "Processing $($rawRecords.Count) raw records from zone [$($this.ZoneName)]..."

            $results = [System.Collections.Generic.List[PSCustomObject]]::new()

            foreach ($record in $rawRecords) {
                if ($record.RecordType -in @('NS', 'SOA') -and 'All' -in $this.RRType -and -not $PSBoundParameters.ContainsKey('RRType')) {
                    continue
                }

                if ('All' -notin $this.RRType -and $record.RecordType -notin $this.RRType) {
                    continue
                }

                $isDynamic = ($null -ne $record.TimeStamp) -and ($record.TimeStamp -ne [System.TimeSpan]::Zero)
                $currentNature = if ($isDynamic) { 'Dynamic' } else { 'Static' }

                if ($this.RecordType -ne 'All' -and $currentNature -ne $this.RecordType) {
                    continue
                }

                $targetData = $this.ExtractTargetData($record)
                $evalIpAddress = $this.ExtractEvalIpAddress($record)

                if (-not $this.EvaluateIPScope($evalIpAddress)) {
                    continue
                }

                $rawHostName = $record.HostName
                $isFqdnAnomaly = $rawHostName.EndsWith(".$($this.ZoneName)", [System.StringComparison]::OrdinalIgnoreCase)

                $sanitizedHostName = if ($isFqdnAnomaly) {
                    $rawHostName.Substring(0, $rawHostName.Length - ($this.ZoneName.Length + 1))
                }
                else {
                    $rawHostName
                }

                if (-not [string]::IsNullOrWhiteSpace($this.SearchTerm)) {
                    $cleanPattern = $this.SearchTerm.Trim()

                    $matchRawHost   = $rawHostName -like $cleanPattern
                    $matchCleanHost = $sanitizedHostName -like $cleanPattern
                    $matchTarget    = (-not [string]::IsNullOrEmpty($targetData)) -and ($targetData -like $cleanPattern)

                    if (-not ($matchRawHost -or $matchCleanHost -or $matchTarget)) {
                        continue
                    }
                }

                $results.Add([PSCustomObject]@{
                    HostName          = $rawHostName
                    SanitizedHostName = $sanitizedHostName
                    RecordType        = $record.RecordType
                    Nature            = $currentNature
                    TargetData        = $targetData
                    IsFqdnAnomaly     = $isFqdnAnomaly
                    TimeStamp         = if ($isDynamic) { $record.TimeStamp } else { 'Static (No TimeStamp)' }
                    ZoneName          = $this.ZoneName
                })
            }

            Write-Verbose -Message "DNS Search Execution Completed Successfully. Found $($results.Count) matching records."
            return $results.ToArray()
        }
        catch [System.UnauthorizedAccessException] {
            Write-Error -Message "Access denied querying DNS zone '$($this.ZoneName)': $($_.Exception.Message)" -ErrorAction Stop
        }
        catch [System.Exception] {
            $rootCause = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
            Write-Error -Message "Unhandled exception executing DNS search query: $rootCause" -ErrorAction Stop
        }
        finally {
            $this.DisposeCimSession()
        }
    }
}
