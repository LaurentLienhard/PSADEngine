function Search-PSADServerDnsRecord {
    <#
    .SYNOPSIS
        Searches AD-integrated DNS records by Name, IP/Target, Nature, Resource Record Type, and IP Scope.
    .DESCRIPTION
        Queries Active Directory integrated DNS zones using the DnsServer module.
        Filters entries based on record nature (Static vs Dynamic), strictly validated Resource Record Types,
        and evaluates target IP addresses against an array of IP subnets (CIDR notation or IP prefixes)
        using high-performance bitwise subnet mask comparisons.
    .PARAMETER SearchTerm
        Optional IP address, IP prefix, HostName, or FQDN pattern to search for. Supports wildcard patterns (*).
    .PARAMETER RecordType
        Filters records by lifecycle nature: Static, Dynamic, or All. Defaults to All.
    .PARAMETER RRType
        Filters records by a validated list of DNS Resource Record Types. Defaults to All.
    .PARAMETER IPScope
        Optional array of IP Subnets in CIDR notation (e.g. '10.0.3.0/24', '10.1.0.0/16') or IP prefixes to filter records against.
    .PARAMETER ZoneName
        The target DNS zone name. Defaults to the current Active Directory domain root zone.
    .PARAMETER Server
        Target Domain Controller or DNS Server. Defaults to local context.
    .PARAMETER Credential
        Optional explicit PSCredential object for authenticating against the remote DNS server via CIM.
    .EXAMPLE
        Search-PSADServerDnsRecord -IPScope '10.0.3.0/24' -RecordType Dynamic -Server 'DC01.corp.contoso.com'
    .EXAMPLE
        Search-PSADServerDnsRecord -IPScope @('10.0.3.0/24', '10.1.2.0/24') -RRType 'A' -RecordType Static
    .EXAMPLE
        Search-PSADServerDnsRecord -SearchTerm 'caw1pbastion*' -RRType 'A' -Server 'DC01.corp.contoso.com' -Credential (Get-Credential)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SearchTerm,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Static', 'Dynamic', 'All')]
        [string]$RecordType = 'All',

        [Parameter(Mandatory = $false)]
        [ValidateSet('A', 'AAAA', 'CNAME', 'PTR', 'TXT', 'MX', 'SRV', 'SOA', 'NS', 'All')]
        [string[]]$RRType = @('All'),

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string[]]$IPScope,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$ZoneName,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [PSCredential]
        [System.Management.Automation.Credential()]
        $Credential
    )

    begin {
        $ErrorActionPreference = 'Stop'
        Write-Verbose -Message "Initializing DNS Search Session. NatureFilter: [$RecordType], RRTypeFilter: [$($RRType -join ', ')], IPScopeFilter: [$($IPScope -join ', ')]"

        $cimSession = $null
        $parsedSubnets = [System.Collections.Generic.List[hashtable]]::new()

        # Pre-parse CIDR IP scopes into bitwise byte structures for high-performance matching
        if ($PSBoundParameters.ContainsKey('IPScope') -and $null -ne $IPScope) {
            foreach ($scopeItem in $IPScope) {
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

                        $parsedSubnets.Add(@{
                            Type         = 'CIDR'
                            NetworkBytes = $netBytes
                            MaskBytes    = $maskBytes
                            Original     = $cleanScope
                        })
                    }
                    catch {
                        Write-Warning -Message "Failed to parse CIDR scope '$cleanScope'. Falling back to prefix string matching."
                        $parsedSubnets.Add(@{
                            Type     = 'Prefix'
                            Prefix   = $cleanScope.Split('/')[0]
                            Original = $cleanScope
                        })
                    }
                }
                else {
                    $parsedSubnets.Add(@{
                        Type     = 'Prefix'
                        Prefix   = $cleanScope
                        Original = $cleanScope
                    })
                }
            }
            Write-Verbose -Message "Pre-parsed $($parsedSubnets.Count) IP scope mask(s)."
        }

        # Auto-detect domain root zone if omitted
        if (-not $PSBoundParameters.ContainsKey('ZoneName') -or [string]::IsNullOrWhiteSpace($ZoneName)) {
            try {
                $ZoneName = (Get-ADDomain).DNSRoot
                Write-Verbose -Message "No ZoneName provided. Defaulted to AD Domain Root: $ZoneName"
            }
            catch [System.Exception] {
                $rootCause = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
                Write-Error -Message "Failed to auto-detect Active Directory Domain Root Zone: $rootCause" -ErrorAction Stop
            }
        }
    }

    process {
        try {
            # Construct dynamic hashtable for Get-DnsServerResourceRecord Splatting
            $getDnsParams = @{
                ZoneName    = $ZoneName
                ErrorAction = 'Stop'
            }

            # Handle remote authentication using CIM Session if Credential is provided
            if ($PSBoundParameters.ContainsKey('Credential')) {
                $targetComputer = if ($PSBoundParameters.ContainsKey('Server')) { $Server } else { 'localhost' }
                Write-Verbose -Message "Establishing authenticated CIM Session to [$targetComputer] with user [$($Credential.UserName)]..."

                $cimSessionParams = @{
                    ComputerName = $targetComputer
                    Credential   = $Credential
                    ErrorAction  = 'Stop'
                }
                $cimSession = New-CimSession @cimSessionParams
                $getDnsParams['CimSession'] = $cimSession
            }
            elseif ($PSBoundParameters.ContainsKey('Server')) {
                $getDnsParams['ComputerName'] = $Server
            }

            Write-Verbose -Message "Fetching raw DNS records from zone [$ZoneName]..."
            $rawRecords = Get-DnsServerResourceRecord @getDnsParams
            Write-Verbose -Message "Processing $($rawRecords.Count) raw records from zone [$ZoneName]..."

            foreach ($record in $rawRecords) {
                # Skip SOA and NS infrastructure records unless explicitly requested in RRType
                if ($record.RecordType -in @('NS', 'SOA') -and 'All' -in $RRType -and -not $PSBoundParameters.ContainsKey('RRType')) {
                    continue
                }

                # Evaluate Resource Record Type (RRType) Filter
                if ('All' -notin $RRType -and $record.RecordType -notin $RRType) {
                    continue
                }

                # Evaluate Static vs Dynamic nature via TimeStamp property
                $isDynamic = ($null -ne $record.TimeStamp) -and ($record.TimeStamp -ne [System.TimeSpan]::Zero)
                $currentNature = if ($isDynamic) { 'Dynamic' } else { 'Static' }

                # Apply RecordType filter (Static, Dynamic, All)
                if ($RecordType -ne 'All' -and $currentNature -ne $RecordType) {
                    continue
                }

                # Extract Target / IP / Data based on Record Type
                $targetData = switch ($record.RecordType) {
                    'A'     { [string]$record.RecordData.IPv4Address.IPAddressToString }
                    'AAAA'  { [string]$record.RecordData.IPv6Address.IPAddressToString }
                    'CNAME' { [string]$record.RecordData.HostNameAlias }
                    'PTR'   { [string]$record.RecordData.PtrDomainName }
                    'TXT'   { [string]($record.RecordData.DescriptiveText -join ' ') }
                    'MX'    { [string]$record.RecordData.MailExchange }
                    'SRV'   { [string]"$($record.RecordData.DomainName):$($record.RecordData.Port)" }
                    Default { [string]$record.RecordData.ToString() }
                }

                # Extract pure IP address for IPScope bitwise evaluation
                $evalIpAddress = $null
                if ($record.RecordType -eq 'A') {
                    $evalIpAddress = [string]$record.RecordData.IPv4Address.IPAddressToString
                }
                elseif ($record.RecordType -eq 'AAAA') {
                    $evalIpAddress = [string]$record.RecordData.IPv6Address.IPAddressToString
                }

                # Evaluate IPScope Bitwise Filter
                if ($parsedSubnets.Count -gt 0) {
                    if ([string]::IsNullOrEmpty($evalIpAddress)) {
                        continue
                    }

                    $isScopeMatched = $false

                    foreach ($subnetObj in $parsedSubnets) {
                        if ($subnetObj.Type -eq 'CIDR') {
                            try {
                                $targetIP = [System.Net.IPAddress]::Parse($evalIpAddress)
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
                                        $isScopeMatched = $true
                                        break
                                    }
                                }
                            }
                            catch {
                                # Ignore parsing errors on non-standard IP formats
                            }
                        }
                        elseif ($subnetObj.Type -eq 'Prefix') {
                            if ($evalIpAddress.StartsWith($subnetObj.Prefix)) {
                                $isScopeMatched = $true
                                break
                            }
                        }
                    }

                    if (-not $isScopeMatched) {
                        continue
                    }
                }

                # Detect FQDN anomalous naming (e.g. host.corp.contoso.com registered inside corp.contoso.com)
                $rawHostName = $record.HostName
                $isFqdnAnomaly = $rawHostName.EndsWith(".$ZoneName", [System.StringComparison]::OrdinalIgnoreCase)

                $sanitizedHostName = if ($isFqdnAnomaly) {
                    $rawHostName.Substring(0, $rawHostName.Length - ($ZoneName.Length + 1))
                } else {
                    $rawHostName
                }

                # Apply SearchTerm evaluation against HostName or TargetData
                if (-not [string]::IsNullOrWhiteSpace($SearchTerm)) {
                    $cleanPattern = $SearchTerm.Trim()

                    $matchRawHost   = $rawHostName -like $cleanPattern
                    $matchCleanHost = $sanitizedHostName -like $cleanPattern
                    $matchTarget    = (-not [string]::IsNullOrEmpty($targetData)) -and ($targetData -like $cleanPattern)

                    if (-not ($matchRawHost -or $matchCleanHost -or $matchTarget)) {
                        continue
                    }
                }

                [PSCustomObject]@{
                    HostName          = $rawHostName
                    SanitizedHostName = $sanitizedHostName
                    RecordType        = $record.RecordType
                    Nature            = $currentNature
                    TargetData        = $targetData
                    IsFqdnAnomaly     = $isFqdnAnomaly
                    TimeStamp         = if ($isDynamic) { $record.TimeStamp } else { 'Static (No TimeStamp)' }
                    ZoneName          = $ZoneName
                }
            }
        }
        catch [System.UnauthorizedAccessException] {
            Write-Error -Message "Access denied querying DNS zone '$ZoneName': $($_.Exception.Message)" -ErrorAction Stop
        }
        catch [System.Exception] {
            $rootCause = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
            Write-Error -Message "Unhandled exception executing DNS search query: $rootCause" -ErrorAction Stop
        }
        finally {
            if ($null -ne $cimSession) {
                Write-Verbose -Message "Disposing active CIM session..."
                Remove-CimSession -CimSession $cimSession -ErrorAction SilentlyContinue
            }
        }
    }

    end {
        Write-Verbose -Message "DNS Search Execution Completed Successfully."
    }
}
