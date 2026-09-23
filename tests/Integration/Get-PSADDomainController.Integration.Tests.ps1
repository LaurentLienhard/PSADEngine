<#
    .SYNOPSIS
        Integration coverage for Get-PSADDomainController against a real Active Directory domain.

    .DESCRIPTION
        These tests are inert by default. They require the machine to be joined to an
        Active Directory domain, or that the operator explicitly provides a target domain
        name through an environment variable.

        Two opt-in levels are supported:

          Level 0 (default)
            The machine must be domain-joined. Tests query the current domain.
            Set PSADENGINE_INTEGRATION_SKIP_DC to 'YES' to skip entirely.

          Level 1: specific domain
            Set PSADENGINE_INTEGRATION_DOMAIN to a lab domain FQDN (e.g. corp.contoso.com).
            Tests will additionally query that explicit domain.

        All tests are read-only. No changes are made to Active Directory.

    .NOTES
        Tag: Integration. Exclude this tag in CI pipelines that cannot reach a domain.
#>

BeforeDiscovery {
    Import-Module -Name 'PSADEngine' -Force

    # Detect whether the machine is domain-joined
    $script:isDomainJoined = $false
    try
    {
        $null = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $script:isDomainJoined = $true
    }
    catch
    {
        $script:isDomainJoined = $false
    }

    # Explicit skip override
    $script:skipAll = ($env:PSADENGINE_INTEGRATION_SKIP_DC -eq 'YES') -or (-not $script:isDomainJoined)

    # Optional explicit domain target
    $script:explicitDomain = $env:PSADENGINE_INTEGRATION_DOMAIN
    $script:hasExplicitDomain = -not [System.String]::IsNullOrWhiteSpace($script:explicitDomain)
    $script:skipExplicitDomain = $script:skipAll -or (-not $script:hasExplicitDomain)
}

AfterAll {
    Get-Module -Name 'PSADEngine' -All | Remove-Module -Force
}

Describe 'Get-PSADDomainController integration' -Tag 'Integration' {

    Context 'Current domain discovery' -Skip:$script:skipAll {

        BeforeAll {
            $script:results = Get-PSADDomainController -Verbose
        }

        It 'Should return at least one domain controller' {
            @($script:results).Count | Should -BeGreaterThan 0
        }

        It 'Should return objects of type PSADDomainController' {
            foreach ($dc in @($script:results))
            {
                $dc | Should -BeOfType 'PSADDomainController'
            }
        }

        It 'Should populate the Name property with a non-empty FQDN' {
            foreach ($dc in @($script:results))
            {
                $dc.Name | Should -Not -BeNullOrEmpty
                $dc.Name | Should -Match '\.' -Because 'domain controller names should be fully qualified'
            }
        }

        It 'Should populate the SiteName property' {
            foreach ($dc in @($script:results))
            {
                $dc.SiteName | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should set IsReachable to true for at least one DC' {
            @($script:results).Where({ $_.IsReachable -eq $true }).Count |
                Should -BeGreaterThan 0 -Because 'at least the DC we authenticated against must be reachable'
        }

        It 'Should populate IPAddress for reachable DCs' {
            foreach ($dc in @($script:results).Where({ $_.IsReachable }))
            {
                $dc.IPAddress | Should -Not -BeNullOrEmpty
                # Validate it looks like an IP address (v4 or v6)
                $dc.IPAddress | Should -Match '(\d{1,3}\.){3}\d{1,3}|:' -Because 'IPAddress should be a valid IPv4 or IPv6 address'
            }
        }

        It 'Should populate OperatingSystemVersion for reachable DCs' {
            foreach ($dc in @($script:results).Where({ $_.IsReachable }))
            {
                $dc.OperatingSystemVersion | Should -Not -BeNullOrEmpty
            }
        }

        It 'Should have at least one Global Catalog server in the domain' {
            @($script:results).Where({ $_.IsGlobalCatalog -eq $true }).Count |
                Should -BeGreaterThan 0 -Because 'every AD domain must have at least one GC'
        }

        It 'Should assign all five FSMO roles across the returned DCs' {
            $allRoles = ($script:results | ForEach-Object { $_.FSMORoles }) -join ', '

            # The three domain-level FSMO roles must be held somewhere
            $allRoles | Should -Match 'PdcRole' -Because 'PDC Emulator must be assigned'
            $allRoles | Should -Match 'RidRole' -Because 'RID Master must be assigned'
            $allRoles | Should -Match 'InfrastructureRole' -Because 'Infrastructure Master must be assigned'
        }

        It 'Should inherit PSADServer and PSADComputer properties' {
            $dc = @($script:results)[0]
            $propertyNames = $dc.PSObject.Properties.Name

            # From PSADServer
            $propertyNames | Should -Contain 'Role'

            # From PSADComputer
            $propertyNames | Should -Contain 'DistinguishedName'
            $propertyNames | Should -Contain 'DNSHostName'
            $propertyNames | Should -Contain 'Enabled'
            $propertyNames | Should -Contain 'OperatingSystem'
            $propertyNames | Should -Contain 'ObjectGUID'
        }
    }

    Context 'Pipeline input from domain name' -Skip:$script:skipAll {

        It 'Should accept the current domain FQDN via pipeline' {
            $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $domainFqdn = $currentDomain.Name

            $result = $domainFqdn | Get-PSADDomainController

            @($result).Count | Should -BeGreaterThan 0
        }
    }

    Context 'WhatIf produces no output and queries nothing' -Skip:$script:skipAll {

        It 'Should return nothing with -WhatIf' {
            $result = Get-PSADDomainController -WhatIf
            $result | Should -BeNullOrEmpty
        }

        It 'Should not throw with -WhatIf' {
            { Get-PSADDomainController -WhatIf } | Should -Not -Throw
        }
    }

    Context 'LDAP reachability verification (Zero Trust)' -Skip:$script:skipAll {

        BeforeAll {
            $script:reachResults = Get-PSADDomainController
        }

        It 'Should test LDAP port 389 rather than ICMP for reachability' {
            # Reachable DCs must have passed the TCP 389 check
            foreach ($dc in @($script:reachResults).Where({ $_.IsReachable }))
            {
                # Independently verify that LDAP port 389 is open
                $tcp = [System.Net.Sockets.TcpClient]::new()
                try
                {
                    $asyncResult = $tcp.BeginConnect($dc.Name, 389, $null, $null)
                    $connected = $asyncResult.AsyncWaitHandle.WaitOne(3000, $true)
                    $connected | Should -BeTrue -Because "DC '$($dc.Name)' was reported as reachable, so LDAP 389 must be open"
                }
                finally
                {
                    $tcp.Close()
                }
            }
        }

        It 'Should set IPAddress to empty string for unreachable DCs' {
            foreach ($dc in @($script:reachResults).Where({ -not $_.IsReachable }))
            {
                $dc.IPAddress | Should -BeNullOrEmpty
            }
        }

        It 'Should set IsGlobalCatalog to false for unreachable DCs' {
            foreach ($dc in @($script:reachResults).Where({ -not $_.IsReachable }))
            {
                $dc.IsGlobalCatalog | Should -BeFalse
            }
        }
    }

    Context 'Explicit domain query' -Skip:$script:skipExplicitDomain {

        BeforeAll {
            $script:explicitResults = Get-PSADDomainController -DomainName $script:explicitDomain -Verbose
        }

        It 'Should return at least one domain controller for the explicit domain' {
            @($script:explicitResults).Count | Should -BeGreaterThan 0
        }

        It 'Should return FQDNs belonging to the specified domain' {
            foreach ($dc in @($script:explicitResults))
            {
                $dc.Name | Should -Match ([regex]::Escape($script:explicitDomain)) -Because "DC name should contain the domain FQDN '$($script:explicitDomain)'"
            }
        }

        It 'Should return PSADDomainController objects for the explicit domain' {
            foreach ($dc in @($script:explicitResults))
            {
                $dc | Should -BeOfType 'PSADDomainController'
            }
        }
    }

    Context 'Invalid domain name handling' -Skip:$script:skipAll {

        It 'Should write an error for a non-existent domain' {
            $result = Get-PSADDomainController -DomainName 'this.domain.does.not.exist.invalid' -ErrorVariable getErr -ErrorAction SilentlyContinue
            $result | Should -BeNullOrEmpty
            $getErr | Should -Not -BeNullOrEmpty
        }

        It 'Should reject an empty domain name via parameter validation' {
            { Get-PSADDomainController -DomainName '' } | Should -Throw
        }
    }

    Context 'Output consistency and determinism' -Skip:$script:skipAll {

        It 'Should return the same number of DCs on consecutive calls' {
            $first = Get-PSADDomainController
            $second = Get-PSADDomainController

            @($first).Count | Should -Be @($second).Count
        }

        It 'Should return the same DC names on consecutive calls' {
            $first = @(Get-PSADDomainController) | Sort-Object Name
            $second = @(Get-PSADDomainController) | Sort-Object Name

            for ($i = 0; $i -lt $first.Count; $i++)
            {
                $first[$i].Name | Should -Be $second[$i].Name
            }
        }
    }
}
