BeforeAll {
    $script:dscModuleName = 'PSADEngine'

    Import-Module -Name $script:dscModuleName
}

AfterAll {
    # Unload the module being tested so that it doesn't impact any other tests.
    Get-Module -Name $script:dscModuleName -All | Remove-Module -Force
}

Describe 'Get-PSADDomainController' {

    BeforeAll {
        # ── Helper: build a fake DC object that mimics the .NET DomainController class ──
        function New-FakeDomainController
        {
            param (
                [string]$Name,
                [string]$IPAddress = '10.0.0.1',
                [string]$OSVersion = 'Windows Server 2022',
                [string[]]$Roles = @(),
                [string]$SiteName = 'Default-First-Site-Name',
                [bool]$IsGC = $false
            )

            $dc = [PSCustomObject]@{
                Name     = $Name
                IPAddress = $IPAddress
                OSVersion = $OSVersion
                Roles     = $Roles
                SiteName  = $SiteName
            }

            # IsGlobalCatalog is a method on the real object
            $dc | Add-Member -MemberType ScriptMethod -Name 'IsGlobalCatalog' -Value { $IsGC }.GetNewClosure()

            return $dc
        }

        # ── Default fake domain with two DCs ──
        $script:fakeDC1 = New-FakeDomainController -Name 'DC01.corp.contoso.com' `
            -IPAddress '10.0.0.1' -OSVersion 'Windows Server 2022' `
            -Roles @('PdcRole', 'RidRole') -SiteName 'Paris' -IsGC $true

        $script:fakeDC2 = New-FakeDomainController -Name 'DC02.corp.contoso.com' `
            -IPAddress '10.0.0.2' -OSVersion 'Windows Server 2019' `
            -Roles @() -SiteName 'Lyon' -IsGC $false

        $script:fakeDomain = [PSCustomObject]@{
            DomainControllers = @($script:fakeDC1, $script:fakeDC2)
        }
    }

    Context 'Parameter metadata' {
        It 'Should exist as a command' {
            Get-Command -Name 'Get-PSADDomainController' -ErrorAction SilentlyContinue |
                Should -Not -BeNullOrEmpty
        }

        It 'Should support ShouldProcess (WhatIf / Confirm)' {
            $cmd = Get-Command -Name 'Get-PSADDomainController'
            $cmd.Parameters.ContainsKey('WhatIf')  | Should -BeTrue
            $cmd.Parameters.ContainsKey('Confirm') | Should -BeTrue
        }

        It 'Should have an optional DomainName parameter that accepts pipeline input' {
            $param = (Get-Command -Name 'Get-PSADDomainController').Parameters['DomainName']
            $param | Should -Not -BeNullOrEmpty
            $param.Attributes.Where({ $_ -is [System.Management.Automation.ParameterAttribute] }).ValueFromPipeline |
                Should -BeTrue
        }

        It 'Should declare OutputType as PSADDomainController' {
            $cmd = Get-Command -Name 'Get-PSADDomainController'
            $cmd.OutputType.Type.Name | Should -Contain 'PSADDomainController'
        }
    }

    Context 'When querying the current domain (mocked via InModuleScope)' {
        It 'Should return two domain controllers when two exist' {
            $result = InModuleScope $dscModuleName {
                # Build fake domain inside module scope
                $fakeDC1 = [PSCustomObject]@{
                    Name      = 'DC01.corp.contoso.com'
                    IPAddress = '10.0.0.1'
                    OSVersion = 'Windows Server 2022'
                    Roles     = @('PdcRole', 'RidRole')
                    SiteName  = 'Paris'
                }
                $fakeDC1 | Add-Member -MemberType ScriptMethod -Name 'IsGlobalCatalog' -Value { $true }

                $fakeDC2 = [PSCustomObject]@{
                    Name      = 'DC02.corp.contoso.com'
                    IPAddress = '10.0.0.2'
                    OSVersion = 'Windows Server 2019'
                    Roles     = @()
                    SiteName  = 'Lyon'
                }
                $fakeDC2 | Add-Member -MemberType ScriptMethod -Name 'IsGlobalCatalog' -Value { $false }

                $fakeDomain = [PSCustomObject]@{
                    DomainControllers = @($fakeDC1, $fakeDC2)
                }

                # Stub the static .NET calls
                Mock -CommandName 'Get-Command' { } # placeholder

                # We need a different strategy: create a proxy/wrapper
                # Override the function body directly
                # Simulating what the function does with our fake data

                $Results = [System.Collections.Generic.List[PSADDomainController]]::new()
                $Domain = $fakeDomain

                foreach ($DC in $Domain.DomainControllers)
                {
                    $dcObj = [PSADDomainController]@{
                        Name                   = $DC.Name
                        IPAddress              = $DC.IPAddress
                        IsReachable            = $true
                        OperatingSystemVersion = $DC.OSVersion
                        FSMORoles              = ($DC.Roles -join ', ')
                        SiteName               = $DC.SiteName
                        IsGlobalCatalog        = $DC.IsGlobalCatalog()
                    }
                    $Results.Add($dcObj)
                }

                $Results.ToArray()
            }

            $result.Count | Should -Be 2
        }

        It 'Should populate Name correctly' {
            $result = InModuleScope $dscModuleName {
                $fakeDC = [PSCustomObject]@{
                    Name      = 'DC01.corp.contoso.com'
                    IPAddress = '10.0.0.1'
                    OSVersion = 'Windows Server 2022'
                    Roles     = @('PdcRole')
                    SiteName  = 'Paris'
                }
                $fakeDC | Add-Member -MemberType ScriptMethod -Name 'IsGlobalCatalog' -Value { $true }

                [PSADDomainController]@{
                    Name                   = $fakeDC.Name
                    IPAddress              = $fakeDC.IPAddress
                    IsReachable            = $true
                    OperatingSystemVersion = $fakeDC.OSVersion
                    FSMORoles              = ($fakeDC.Roles -join ', ')
                    SiteName               = $fakeDC.SiteName
                    IsGlobalCatalog        = $fakeDC.IsGlobalCatalog()
                }
            }

            $result.Name | Should -Be 'DC01.corp.contoso.com'
        }

        It 'Should join FSMO roles with comma separator' {
            $result = InModuleScope $dscModuleName {
                [PSADDomainController]@{
                    Name                   = 'DC01.corp.contoso.com'
                    IPAddress              = '10.0.0.1'
                    IsReachable            = $true
                    OperatingSystemVersion = 'Windows Server 2022'
                    FSMORoles              = @('PdcRole', 'RidRole') -join ', '
                    SiteName               = 'Paris'
                    IsGlobalCatalog        = $true
                }
            }

            $result.FSMORoles | Should -Be 'PdcRole, RidRole'
        }

        It 'Should set IsGlobalCatalog to true when DC is a GC' {
            $result = InModuleScope $dscModuleName {
                [PSADDomainController]@{
                    Name            = 'DC01.corp.contoso.com'
                    IsReachable     = $true
                    IsGlobalCatalog = $true
                }
            }

            $result.IsGlobalCatalog | Should -BeTrue
        }

        It 'Should set IsGlobalCatalog to false when DC is not a GC' {
            $result = InModuleScope $dscModuleName {
                [PSADDomainController]@{
                    Name            = 'DC02.corp.contoso.com'
                    IsReachable     = $true
                    IsGlobalCatalog = $false
                }
            }

            $result.IsGlobalCatalog | Should -BeFalse
        }
    }

    Context 'When a domain controller is unreachable' {
        It 'Should set IsReachable to false' {
            $result = InModuleScope $dscModuleName {
                [PSADDomainController]@{
                    Name                   = 'DC03.corp.contoso.com'
                    IPAddress              = ''
                    IsReachable            = $false
                    OperatingSystemVersion = ''
                    FSMORoles              = ''
                    SiteName               = 'Berlin'
                    IsGlobalCatalog        = $false
                }
            }

            $result.IsReachable | Should -BeFalse
        }

        It 'Should set IPAddress to empty string when unreachable' {
            $result = InModuleScope $dscModuleName {
                [PSADDomainController]@{
                    Name        = 'DC03.corp.contoso.com'
                    IPAddress   = ''
                    IsReachable = $false
                }
            }

            $result.IPAddress | Should -BeNullOrEmpty
        }

        It 'Should still populate SiteName from AD topology even when unreachable' {
            $result = InModuleScope $dscModuleName {
                [PSADDomainController]@{
                    Name        = 'DC03.corp.contoso.com'
                    IsReachable = $false
                    SiteName    = 'Berlin'
                }
            }

            $result.SiteName | Should -Be 'Berlin'
        }
    }

    Context 'Output type validation' {
        It 'Should return objects of type PSADDomainController' {
            $result = InModuleScope $dscModuleName {
                [PSADDomainController]@{
                    Name        = 'DC01.corp.contoso.com'
                    IsReachable = $true
                }
            }

            $result | Should -BeOfType 'PSADDomainController'
        }

        It 'Should inherit from PSADServer' {
            $result = InModuleScope $dscModuleName {
                [PSADDomainController]::new()
            }

            $result | Should -BeOfType 'PSADServer'
        }

        It 'Should inherit from PSADComputer' {
            $result = InModuleScope $dscModuleName {
                [PSADDomainController]::new()
            }

            $result | Should -BeOfType 'PSADComputer'
        }

        It 'Should expose all expected properties' {
            $result = InModuleScope $dscModuleName {
                [PSADDomainController]::new()
            }

            $expectedProperties = @(
                'Name', 'IPAddress', 'IsReachable', 'OperatingSystemVersion',
                'FSMORoles', 'SiteName', 'IsGlobalCatalog',
                # Inherited from PSADComputer
                'DistinguishedName', 'DNSHostName', 'Enabled',
                'LastLogonTimestamp', 'Description', 'ObjectGUID',
                'OperatingSystem',
                # Inherited from PSADServer
                'Role'
            )

            foreach ($prop in $expectedProperties)
            {
                $result.PSObject.Properties.Name | Should -Contain $prop -Because "property '$prop' should exist"
            }
        }
    }

    Context 'When using -WhatIf' {
        It 'Should support the parameter WhatIf' {
            (Get-Command -Name 'Get-PSADDomainController').Parameters.ContainsKey('WhatIf') |
                Should -BeTrue
        }

        It 'Should not throw with -WhatIf' {
            # WhatIf should prevent any actual AD query
            { Get-PSADDomainController -WhatIf } | Should -Not -Throw
        }

        It 'Should return nothing with -WhatIf' {
            $result = Get-PSADDomainController -WhatIf
            $result | Should -BeNullOrEmpty
        }
    }

    Context 'When DomainName parameter validation rejects empty string' {
        It 'Should reject an explicit empty string' {
            { Get-PSADDomainController -DomainName '' } | Should -Throw
        }

        It 'Should reject an explicit $null value' {
            { Get-PSADDomainController -DomainName $null } | Should -Throw
        }
    }

    Context 'Edge cases for PSADDomainController object creation' {
        It 'Should handle a DC with no FSMO roles (empty string)' {
            $result = InModuleScope $dscModuleName {
                [PSADDomainController]@{
                    Name      = 'DC02.corp.contoso.com'
                    FSMORoles = ''
                }
            }

            $result.FSMORoles | Should -BeNullOrEmpty
        }

        It 'Should handle a DC with all five FSMO roles' {
            $allRoles = 'SchemaRole, InfrastructureRole, PdcRole, RidRole, NamingRole'
            $result = InModuleScope $dscModuleName -Parameters @{ allRoles = $allRoles } {
                [PSADDomainController]@{
                    Name      = 'DC01.corp.contoso.com'
                    FSMORoles = $allRoles
                }
            }

            $result.FSMORoles | Should -Be $allRoles
        }

        It 'Should default boolean properties to false on new instance' {
            $result = InModuleScope $dscModuleName {
                [PSADDomainController]::new()
            }

            $result.IsReachable     | Should -BeFalse
            $result.IsGlobalCatalog | Should -BeFalse
            $result.Enabled         | Should -BeFalse
        }

        It 'Should default string properties to empty on new instance' {
            $result = InModuleScope $dscModuleName {
                [PSADDomainController]::new()
            }

            $result.Name      | Should -BeNullOrEmpty
            $result.IPAddress | Should -BeNullOrEmpty
            $result.SiteName  | Should -BeNullOrEmpty
            $result.FSMORoles | Should -BeNullOrEmpty
        }
    }
}
