function Get-PSADServerScopeDefinition {
    <#
    .SYNOPSIS
        Generates agnostic IPv4 subnet definitions, range boundaries, and CIDR masks for any network scheme.
    .DESCRIPTION
        Provides fully decoupled, high-performance IPv4 subnet calculations. Accepts explicit CIDR subnets
        or dynamic pattern templates (e.g. '10.{0}.2.0/24') combined with segment IDs. Computes network address,
        broadcast address, usable host ranges, default gateways, and total host counts using overflow-safe bitwise .NET operations.
    .PARAMETER Subnet
        Direct IPv4 subnet in CIDR notation (e.g. '10.1.2.0/24' or '192.168.100.0/22').
    .PARAMETER SubnetTemplate
        A format string pattern containing an index placeholder '{0}' for dynamic segment substitution (e.g. '172.16.{0}.0/23').
    .PARAMETER SegmentId
        An array of integer segment/site identifiers to inject into the SubnetTemplate.
    .PARAMETER GatewayStrategy
        Determines the default gateway IP calculation: FirstUsable (e.g. .1), LastUsable (e.g. .254), or None. Defaults to LastUsable.
    .EXAMPLE
        Get-ADServerScopeDefinition -Subnet '10.10.2.0/24'
    .EXAMPLE
        Get-ADServerScopeDefinition -SubnetTemplate '10.{0}.2.0/24' -SegmentId 1..5
    .EXAMPLE
        1..10 | Get-ADServerScopeDefinition -SubnetTemplate '172.16.{0}.0/23' -GatewayStrategy FirstUsable
    #>
    [CmdletBinding(DefaultParameterSetName = 'DirectSubnet')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'DirectSubnet', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidatePattern('^([0-9]{1,3}\.){3}[0-9]{1,3}\/([0-9]|[1-2][0-9]|3[0-2])$')]
        [string]$Subnet,

        [Parameter(Mandatory = $true, ParameterSetName = 'TemplateSubnet')]
        [ValidateNotNullOrEmpty()]
        [string]$SubnetTemplate,

        [Parameter(Mandatory = $true, ParameterSetName = 'TemplateSubnet', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [int[]]$SegmentId,

        [Parameter(Mandatory = $false)]
        [ValidateSet('LastUsable', 'FirstUsable', 'None')]
        [string]$GatewayStrategy = 'LastUsable'
    )

    begin {
        $ErrorActionPreference = 'Stop'
        Write-Verbose -Message "Initializing Agnostic Scope Definition Processor. ParameterSet: [$($PSCmdlet.ParameterSetName)]"

        # Helper scriptblock to calculate binary IPv4 math without overflow issues
        $script:CalculateSubnetMath = {
            param (
                [string]$CidrInput,
                [string]$GatewayOption
            )

            $parts = $CidrInput.Split('/')
            $ipAddr = [System.Net.IPAddress]::Parse($parts[0])
            $prefixLength = [int]$parts[1]

            $ipBytes = $ipAddr.GetAddressBytes()

            # Integer division and modulo calculation
            $fullBytes = [int][math]::Truncate($prefixLength / 8)
            $restBits  = $prefixLength % 8

            # Construct 32-bit subnet mask with safe byte truncation (-band 0xFF)
            $maskBytes = [byte[]]::new(4)
            for ($i = 0; $i -lt $fullBytes; $i++) {
                $maskBytes[$i] = 0xff
            }
            if ($restBits -gt 0) {
                $maskBytes[$fullBytes] = [byte]((0xff -shl (8 - $restBits)) -band 0xff)
            }

            # Calculate Network Bytes (IP AND Mask)
            $networkBytes = [byte[]]::new(4)
            for ($i = 0; $i -lt 4; $i++) {
                $networkBytes[$i] = [byte]($ipBytes[$i] -band $maskBytes[$i])
            }

            # Calculate Wildcard Bytes (NOT Mask)
            $wildcardBytes = [byte[]]::new(4)
            for ($i = 0; $i -lt 4; $i++) {
                $wildcardBytes[$i] = [byte]($maskBytes[$i] -bxor 0xff)
            }

            # Calculate Broadcast Bytes (Network OR Wildcard)
            $broadcastBytes = [byte[]]::new(4)
            for ($i = 0; $i -lt 4; $i++) {
                $broadcastBytes[$i] = [byte]($networkBytes[$i] -bor $wildcardBytes[$i])
            }

            # Convert Network and Broadcast to 32-bit Big-Endian integers for boundary calculations
            $networkInt = ([uint32]$networkBytes[0] -shl 24) -bor ([uint32]$networkBytes[1] -shl 16) -bor ([uint32]$networkBytes[2] -shl 8) -bor [uint32]$networkBytes[3]
            $broadcastInt = ([uint32]$broadcastBytes[0] -shl 24) -bor ([uint32]$broadcastBytes[1] -shl 16) -bor ([uint32]$broadcastBytes[2] -shl 8) -bor [uint32]$broadcastBytes[3]

            $totalHosts = [uint32]($broadcastInt - $networkInt + 1)
            $usableHosts = if ($prefixLength -ge 31) { $totalHosts } else { $totalHosts - 2 }

            $firstUsableInt = if ($prefixLength -ge 31) { $networkInt } else { $networkInt + 1 }
            $lastUsableInt  = if ($prefixLength -ge 31) { $broadcastInt } else { $broadcastInt - 1 }

            # Helper scriptblock to convert uint32 back to IPv4 string format
            $intToIp = {
                param([uint32]$val)
                $b = [byte[]]::new(4)
                $b[0] = [byte](($val -shr 24) -band 0xff)
                $b[1] = [byte](($val -shr 16) -band 0xff)
                $b[2] = [byte](($val -shr 8) -band 0xff)
                $b[3] = [byte]($val -band 0xff)
                return ([System.Net.IPAddress]::new($b)).IPAddressToString
            }

            $firstUsableIp  = &$intToIp $firstUsableInt
            $lastUsableIp   = &$intToIp $lastUsableInt
            $networkIpStr   = ([System.Net.IPAddress]::new($networkBytes)).IPAddressToString
            $maskIpStr      = ([System.Net.IPAddress]::new($maskBytes)).IPAddressToString
            $broadcastIpStr = ([System.Net.IPAddress]::new($broadcastBytes)).IPAddressToString

            $defaultGateway = switch ($GatewayOption) {
                'FirstUsable' { $firstUsableIp }
                'LastUsable'  { $lastUsableIp }
                Default       { 'N/A' }
            }

            [PSCustomObject]@{
                CIDRSubnet       = "$networkIpStr/$prefixLength"
                NetworkAddress   = $networkIpStr
                SubnetMask       = $maskIpStr
                BroadcastAddress = $broadcastIpStr
                FirstUsableIP    = $firstUsableIp
                LastUsableIP     = $lastUsableIp
                IPRange          = "$firstUsableIp - $lastUsableIp"
                DefaultGateway   = $defaultGateway
                TotalHosts       = $totalHosts
                UsableHosts      = $usableHosts
            }
        }
    }

    process {
        try {
            if ($PSCmdlet.ParameterSetName -eq 'DirectSubnet') {
                Write-Verbose -Message "Processing direct subnet input: [$Subnet]"
                & $script:CalculateSubnetMath -CidrInput $Subnet -GatewayOption $GatewayStrategy
            }
            elseif ($PSCmdlet.ParameterSetName -eq 'TemplateSubnet') {
                foreach ($id in $SegmentId) {
                    $formattedSubnet = $SubnetTemplate -f $id
                    Write-Verbose -Message "Processing template subnet for Segment ID [$id]: [$formattedSubnet]"

                    $result = & $script:CalculateSubnetMath -CidrInput $formattedSubnet -GatewayOption $GatewayStrategy
                    $result | Add-Member -MemberType NoteProperty -Name 'SegmentId' -Value $id -PassThru
                }
            }
        }
        catch [System.FormatException] {
            Write-Error -Message "Invalid IP address or CIDR format provided: $($_.Exception.Message)" -ErrorAction Stop
        }
        catch [System.Exception] {
            $rootCause = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
            Write-Error -Message "Unhandled error processing scope definition: $rootCause" -ErrorAction Stop
        }
    }

    end {
        Write-Verbose -Message "Scope Definition Processing Completed Successfully."
    }
}
