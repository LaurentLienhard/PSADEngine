<#
    .SYNOPSIS
        Integration coverage for Set-PSADDsrmPassword against a real lab domain controller.

    .DESCRIPTION
        These tests are inert by default. Every destructive block is skipped unless the
        operator explicitly opts in, because a DSRM password reset is an irreversible Tier 0
        credential change and there is no rollback other than knowing the previous value.

        Three opt-in levels are supported:

          Level 0 (default)
            Nothing runs. The suite reports skipped tests only.

          Level 1: read-only
            Set PSADENGINE_INTEGRATION_DC to a lab domain controller name. Runs discovery,
            reachability, privilege and WhatIf coverage. Nothing is changed.

          Level 2: destructive
            Additionally set PSADENGINE_INTEGRATION_DESTRUCTIVE to 'YES-I-UNDERSTAND' and
            provide the new secret through PSADENGINE_INTEGRATION_VAULT plus
            PSADENGINE_INTEGRATION_SECRET, read with Microsoft.PowerShell.SecretManagement.
            Performs a real DSRM password reset on the named domain controller.

        NEVER point these variables at a production domain controller. Use an isolated lab
        forest such as corp.contoso.com built specifically for destructive testing.

    .NOTES
        Tag: Integration. Exclude this tag in CI pipelines that cannot reach a lab forest.
#>

BeforeDiscovery {
    Import-Module -Name 'PSADEngine' -Force

    $script:isWindowsPlatform = ($PSVersionTable.PSVersion.Major -lt 6) -or $IsWindows

    $script:targetDomainController = $env:PSADENGINE_INTEGRATION_DC
    $script:hasTarget = -not [System.String]::IsNullOrWhiteSpace($script:targetDomainController)

    $script:ntdsutilPath = if ($script:isWindowsPlatform)
    {
        Join-Path -Path $env:SystemRoot -ChildPath 'System32\ntdsutil.exe'
    }
    else
    {
        [System.String]::Empty
    }

    $script:hasNtdsutil = $script:isWindowsPlatform -and (Test-Path -Path $script:ntdsutilPath -PathType Leaf)

    # Read-only coverage requires a lab target, Windows and the RSAT tooling.
    $script:skipReadOnly = -not ($script:hasTarget -and $script:hasNtdsutil)

    # Destructive coverage additionally requires the explicit acknowledgement and a secret.
    $script:skipDestructive = $script:skipReadOnly -or
        ($env:PSADENGINE_INTEGRATION_DESTRUCTIVE -ne 'YES-I-UNDERSTAND') -or
        [System.String]::IsNullOrWhiteSpace($env:PSADENGINE_INTEGRATION_VAULT) -or
        [System.String]::IsNullOrWhiteSpace($env:PSADENGINE_INTEGRATION_SECRET)
}

AfterAll {
    Get-Module -Name 'PSADEngine' -All | Remove-Module -Force
}

Describe 'Set-PSADDsrmPassword integration' -Tag 'Integration' {
    BeforeAll {
        $script:targetDomainController = $env:PSADENGINE_INTEGRATION_DC
        $script:auditSource = 'PSADEngine'
        $script:auditLogName = 'Application'
    }

    Context 'Environment prerequisites' -Skip:$script:skipReadOnly {
        It 'Should be running on Windows' {
            (($PSVersionTable.PSVersion.Major -lt 6) -or $IsWindows) | Should -BeTrue
        }

        It 'Should have ntdsutil.exe available from the AD DS and AD LDS Tools RSAT feature' {
            Test-Path -Path (Join-Path -Path $env:SystemRoot -ChildPath 'System32\ntdsutil.exe') -PathType Leaf |
                Should -BeTrue
        }

        It 'Should be running under a Tier 0 principal' {
            $privilege = InModuleScope -ModuleName 'PSADEngine' -ScriptBlock {
                Test-PSADTier0Privilege -SecurityIdentifier (Get-PSADTokenGroupSid -Refresh)
            }

            $privilege.IsTier0 | Should -BeTrue -Because 'a DSRM reset requires Domain Admins, Enterprise Admins or Schema Admins'
        }
    }

    Context 'Target discovery and reachability' -Skip:$script:skipReadOnly {
        It 'Should find the target in the domain controller inventory' {
            $inventory = Get-PSADDomainController -WhatIf:$false -Confirm:$false

            $shortName = ($script:targetDomainController -split '\.')[0]

            @($inventory).Where({ ($_.Name -split '\.')[0] -eq $shortName }).Count |
                Should -BeGreaterThan 0
        }

        It 'Should answer on LDAP port 389' {
            $isReachable = InModuleScope -ModuleName 'PSADEngine' -Parameters @{
                ComputerName = $script:targetDomainController
            } -ScriptBlock {
                Test-PSADLdapConnectivity -ComputerName $ComputerName -Port 389 -TimeoutMilliseconds 5000
            }

            $isReachable | Should -BeTrue
        }
    }

    Context 'Non destructive dry run' -Skip:$script:skipReadOnly {
        BeforeAll {
            <#
                Test material only. A real rotation must take the secret from a vault, which
                is exactly what the destructive context below does.
            #>
            $script:dryRunSecret = ConvertTo-SecureString -String 'Dry-Run-Never-Applied-01!' -AsPlainText -Force
        }

        It 'Should report a Skipped status under WhatIf without changing anything' {
            $dsrmParam = @{
                Identity    = $script:targetDomainController
                NewPassword = $script:dryRunSecret
                WhatIf      = $true
            }

            $result = Set-PSADDsrmPassword @dsrmParam

            $result.Status | Should -Be 'Skipped'
            $result.ComputerName | Should -Match ($script:targetDomainController -split '\.')[0]
        }

        It 'Should reject a weak password before contacting the domain controller' {
            $weak = ConvertTo-SecureString -String 'Passw0rd' -AsPlainText -Force

            { Set-PSADDsrmPassword -Identity $script:targetDomainController -NewPassword $weak -Confirm:$false } |
                Should -Throw -ExpectedMessage '*Tier 0 password policy*'
        }

        It 'Should reject a target that is not a domain controller' {
            $result = Set-PSADDsrmPassword -Identity 'NOT-A-DC-12345' -NewPassword $script:dryRunSecret -WhatIf -ErrorAction SilentlyContinue

            $result.Status | Should -Be 'Failed'
            $result.FailureCategory | Should -Be 'TargetNotFound'
        }
    }

    Context 'Destructive DSRM rotation' -Skip:$script:skipDestructive {
        BeforeAll {
            Import-Module -Name 'Microsoft.PowerShell.SecretManagement' -ErrorAction Stop

            $secretParam = @{
                Name  = $env:PSADENGINE_INTEGRATION_SECRET
                Vault = $env:PSADENGINE_INTEGRATION_VAULT
            }

            $script:vaultSecret = Get-Secret @secretParam

            $script:startTime = [System.DateTime]::Now.AddSeconds(-5)
        }

        It 'Should reset the DSRM password and report Success' {
            $dsrmParam = @{
                Identity    = $script:targetDomainController
                NewPassword = $script:vaultSecret
                Force       = $true
                Verbose     = $true
            }

            $script:rotationResult = Set-PSADDsrmPassword @dsrmParam

            $script:rotationResult.Status | Should -Be 'Success'
        }

        It 'Should report the canonical fully qualified domain controller name' {
            $script:rotationResult.ComputerName | Should -Match '\.'
        }

        It 'Should attribute the change to the acting principal' {
            $script:rotationResult.PerformedBy | Should -Not -BeNullOrEmpty
        }

        It 'Should have written an attempt record to the Windows event log' {
            $eventParam = @{
                LogName     = $script:auditLogName
                ProviderName = $script:auditSource
                StartTime   = $script:startTime
                ErrorAction = 'SilentlyContinue'
            }

            $record = @(Get-WinEvent -FilterHashtable $eventParam)

            @($record).Where({ 9000 -eq $_.Id }).Count | Should -BeGreaterThan 0
        }

        It 'Should have written a success record to the Windows event log' {
            $eventParam = @{
                LogName     = $script:auditLogName
                ProviderName = $script:auditSource
                StartTime   = $script:startTime
                ErrorAction = 'SilentlyContinue'
            }

            $record = @(Get-WinEvent -FilterHashtable $eventParam)

            @($record).Where({ 9001 -eq $_.Id }).Count | Should -BeGreaterThan 0
        }

        It 'Should never write the secret into any audit record' {
            $eventParam = @{
                LogName     = $script:auditLogName
                ProviderName = $script:auditSource
                StartTime   = $script:startTime
                ErrorAction = 'SilentlyContinue'
            }

            $plainSecret = [System.Net.NetworkCredential]::new('', $script:vaultSecret).Password

            foreach ($record in @(Get-WinEvent -FilterHashtable $eventParam))
            {
                $record.Message | Should -Not -Match ([regex]::Escape($plainSecret))
            }
        }

        It 'Should leave the directory service healthy' {
            $dcdiag = & "$env:SystemRoot\System32\dcdiag.exe" /s:$script:targetDomainController /test:services /test:advertising 2>&1 |
                Out-String

            $dcdiag | Should -Not -Match 'failed test'
        }
    }
}
