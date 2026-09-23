function Search-PSADServerDnsRecord {
    <#
    .SYNOPSIS
        Searches AD-integrated DNS records by Name, IP/Target, Nature, and validated Resource Record Type.
    .DESCRIPTION
        Queries Active Directory integrated DNS zones using the DnsServer module.
        Supports explicit credentials via dynamic CIM session creation to handle remote server authentication cleanly.
    .PARAMETER SearchTerm
        Optional IP address, IP prefix, HostName, or FQDN pattern to search for. Supports wildcard patterns (*).
    .PARAMETER RecordType
        Filters records by lifecycle nature: Static, Dynamic, or All. Defaults to All.
    .PARAMETER RRType
        Filters records by a validated list of DNS Resource Record Types. Defaults to All.
    .PARAMETER ZoneName
        The target DNS zone name. Defaults to the current Active Directory domain root zone.
    .PARAMETER Server
        Target Domain Controller or DNS Server. Defaults to the local context.
    .PARAMETER Credential
        Optional explicit PSCredential object for authenticating against the remote DNS server via CIM.
    .EXAMPLE
        Search-PSADServerDnsRecord -RRType 'CNAME' -Server 'caw1pdc03' -Credential (Get-Secret AdmAccount) -Verbose
    .EXAMPLE
        Search-PSPSADServerDnsRecord -SearchTerm 'caw1pbastion*' -RRType 'A', 'AAAA' -RecordType All
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
        Write-Verbose -Message "Initializing DNS Search Session. NatureFilter: [$RecordType], RRTypeFilter: [$($RRType -join ', ')], SearchTerm: [$SearchTerm]"

        $cimSession = $null

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

            # Handle remote authentication using CIM Session if Credential or Server is passed
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

                # Detect FQDN anomalous naming (e.g. host.corp.contoso.com registered inside corp.contoso.com)
                $rawHostName = $record.HostName
                $isFqdnAnomaly = $rawHostName.EndsWith(".$ZoneName", [System.StringComparison]::OrdinalIgnoreCase)

                $sanitizedHostName = if ($isFqdnAnomaly) {
                    $rawHostName.Substring(0, $rawHostName.Length - ($ZoneName.Length + 1))
                } else {
                    $rawHostName
                }

                # Apply SearchTerm evaluation
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
