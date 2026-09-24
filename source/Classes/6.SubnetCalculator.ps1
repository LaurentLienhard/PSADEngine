class SubnetCalculator {
    [string]$Subnet
    [string]$SubnetTemplate
    [int[]]$SegmentId
    [ValidateSet('LastUsable', 'FirstUsable', 'None')]
    [string]$GatewayStrategy = 'LastUsable'

    SubnetCalculator() {
    }

    SubnetCalculator([string]$Subnet) {
        $this.Subnet = $Subnet
    }

    SubnetCalculator([string]$SubnetTemplate, [int[]]$SegmentId, [string]$GatewayStrategy) {
        $this.SubnetTemplate = $SubnetTemplate
        $this.SegmentId = $SegmentId
        $this.GatewayStrategy = $GatewayStrategy
    }

    [string] ConvertUInt32ToIPString([uint32]$Value) {
        $b = [byte[]]::new(4)
        $b[0] = [byte](($Value -shr 24) -band 0xff)
        $b[1] = [byte](($Value -shr 16) -band 0xff)
        $b[2] = [byte](($Value -shr 8) -band 0xff)
        $b[3] = [byte]($Value -band 0xff)
        return ([System.Net.IPAddress]::new($b)).IPAddressToString
    }

    [PSCustomObject] CalculateSubnetMath([string]$CidrInput) {
        $parts = $CidrInput.Split('/')
        $ipAddr = [System.Net.IPAddress]::Parse($parts[0])
        $prefixLength = [int]$parts[1]

        $ipBytes = $ipAddr.GetAddressBytes()

        $fullBytes = [int][math]::Truncate($prefixLength / 8)
        $restBits  = $prefixLength % 8

        $maskBytes = [byte[]]::new(4)
        for ($i = 0; $i -lt $fullBytes; $i++) {
            $maskBytes[$i] = 0xff
        }
        if ($restBits -gt 0) {
            $maskBytes[$fullBytes] = [byte]((0xff -shl (8 - $restBits)) -band 0xff)
        }

        $networkBytes = [byte[]]::new(4)
        for ($i = 0; $i -lt 4; $i++) {
            $networkBytes[$i] = [byte]($ipBytes[$i] -band $maskBytes[$i])
        }

        $wildcardBytes = [byte[]]::new(4)
        for ($i = 0; $i -lt 4; $i++) {
            $wildcardBytes[$i] = [byte]($maskBytes[$i] -bxor 0xff)
        }

        $broadcastBytes = [byte[]]::new(4)
        for ($i = 0; $i -lt 4; $i++) {
            $broadcastBytes[$i] = [byte]($networkBytes[$i] -bor $wildcardBytes[$i])
        }

        $networkInt = ([uint32]$networkBytes[0] -shl 24) -bor ([uint32]$networkBytes[1] -shl 16) -bor ([uint32]$networkBytes[2] -shl 8) -bor [uint32]$networkBytes[3]
        $broadcastInt = ([uint32]$broadcastBytes[0] -shl 24) -bor ([uint32]$broadcastBytes[1] -shl 16) -bor ([uint32]$broadcastBytes[2] -shl 8) -bor [uint32]$broadcastBytes[3]

        $totalHosts = [uint32]($broadcastInt - $networkInt + 1)
        $usableHosts = if ($prefixLength -ge 31) { $totalHosts } else { $totalHosts - 2 }

        $firstUsableInt = if ($prefixLength -ge 31) { $networkInt } else { $networkInt + 1 }
        $lastUsableInt  = if ($prefixLength -ge 31) { $broadcastInt } else { $broadcastInt - 1 }

        $firstUsableIp  = $this.ConvertUInt32ToIPString($firstUsableInt)
        $lastUsableIp   = $this.ConvertUInt32ToIPString($lastUsableInt)
        $networkIpStr   = ([System.Net.IPAddress]::new($networkBytes)).IPAddressToString
        $maskIpStr      = ([System.Net.IPAddress]::new($maskBytes)).IPAddressToString
        $broadcastIpStr = ([System.Net.IPAddress]::new($broadcastBytes)).IPAddressToString

        $defaultGateway = switch ($this.GatewayStrategy) {
            'FirstUsable' { $firstUsableIp }
            'LastUsable'  { $lastUsableIp }
            Default       { 'N/A' }
        }

        return [PSCustomObject]@{
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

    [PSCustomObject[]] Calculate() {
        $ErrorActionPreference = 'Stop'
        Write-Verbose -Message "Initializing Agnostic Scope Definition Processor."

        try {
            $results = [System.Collections.Generic.List[PSCustomObject]]::new()

            if (-not [string]::IsNullOrWhiteSpace($this.Subnet)) {
                Write-Verbose -Message "Processing direct subnet input: [$($this.Subnet)]"
                $result = $this.CalculateSubnetMath($this.Subnet)
                $results.Add($result)
            }
            elseif (-not [string]::IsNullOrWhiteSpace($this.SubnetTemplate) -and $null -ne $this.SegmentId) {
                foreach ($id in $this.SegmentId) {
                    $formattedSubnet = $this.SubnetTemplate -f $id
                    Write-Verbose -Message "Processing template subnet for Segment ID [$id]: [$formattedSubnet]"

                    $result = $this.CalculateSubnetMath($formattedSubnet)
                    $result | Add-Member -MemberType NoteProperty -Name 'SegmentId' -Value $id -PassThru
                    $results.Add($result)
                }
            }

            Write-Verbose -Message "Scope Definition Processing Completed Successfully."
            return $results.ToArray()
        }
        catch [System.FormatException] {
            Write-Error -Message "Invalid IP address or CIDR format provided: $($_.Exception.Message)" -ErrorAction Stop
        }
        catch [System.Exception] {
            $rootCause = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
            Write-Error -Message "Unhandled error processing scope definition: $rootCause" -ErrorAction Stop
        }
        return $null
    }
}
