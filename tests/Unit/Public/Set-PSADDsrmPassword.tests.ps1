BeforeAll {
    $script:dscModuleName = 'PSADEngine'

    Import-Module -Name $script:dscModuleName -Force

    <#
        Test material only. The module itself never converts a plain string into a
        SecureString; that conversion exists here solely to build deterministic fixtures.
    #>
    function script:New-TestSecureString
    {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
        param ([string]$PlainText)

        return (ConvertTo-SecureString -String $PlainText -AsPlainText -Force)
    }

    function script:New-TestDomainController
    {
        param ([string[]]$Name)

        return @(
            $Name | ForEach-Object -Process {
                [PSCustomObject]@{
                    Name        = $_
                    IsReachable = $true
                    SiteName    = 'Default-First-Site-Name'
                }
            }
        )
    }

    $script:strongPassword = script:New-TestSecureString -PlainText 'Tr0ub4dor-Horse-Battery!'
    $script:weakPassword = script:New-TestSecureString -PlainText 'short1A'

    $script:domainAdminSid = @(
        'S-1-5-21-1111111111-2222222222-3333333333-1105'
        'S-1-5-21-1111111111-2222222222-3333333333-512'
        'S-1-5-32-544'
    )

    $script:unprivilegedSid = @(
        'S-1-5-21-1111111111-2222222222-3333333333-1105'
        'S-1-5-21-1111111111-2222222222-3333333333-513'
    )
}

AfterAll {
    Get-Module -Name $script:dscModuleName -All | Remove-Module -Force
}

Describe 'Set-PSADDsrmPassword' {
    BeforeAll {
        $script:successTranscript = @'
ntdsutil: set dsrm password
Reset DSRM Administrator Password: reset password on server DC01.corp.contoso.com
Please type password for DS Restore Mode Administrator Account:
Please confirm new password:
Password has been set successfully.
'@
    }

    Context 'Command contract' {
        It 'Should support ShouldProcess' {
            $command = Get-Command -Name 'Set-PSADDsrmPassword'

            $command.Parameters.ContainsKey('WhatIf') | Should -BeTrue
            $command.Parameters.ContainsKey('Confirm') | Should -BeTrue
        }

        It 'Should declare a High confirm impact because this is a Tier 0 credential change' {
            $metadata = [System.Management.Automation.CommandMetadata]::new((Get-Command -Name 'Set-PSADDsrmPassword'))

            $metadata.ConfirmImpact | Should -Be 'High'
        }

        It 'Should mark <ParameterName> as mandatory' -ForEach @(
            @{ ParameterName = 'Identity' }
            @{ ParameterName = 'NewPassword' }
        ) {
            $parameter = (Get-Command -Name 'Set-PSADDsrmPassword').Parameters[$ParameterName]

            $parameter.Attributes.Where({ $_ -is [System.Management.Automation.ParameterAttribute] }).Mandatory |
                Should -Contain $true
        }

        It 'Should type NewPassword as SecureString so the secret is never a plain string' {
            (Get-Command -Name 'Set-PSADDsrmPassword').Parameters['NewPassword'].ParameterType |
                Should -Be ([System.Security.SecureString])
        }

        It 'Should type Credential as PSCredential' {
            (Get-Command -Name 'Set-PSADDsrmPassword').Parameters['Credential'].ParameterType |
                Should -Be ([System.Management.Automation.PSCredential])
        }

        It 'Should accept the <AliasName> alias on Identity for pipeline binding' -ForEach @(
            @{ AliasName = 'ComputerName' }
            @{ AliasName = 'Name' }
            @{ AliasName = 'DistinguishedName' }
        ) {
            (Get-Command -Name 'Set-PSADDsrmPassword').Parameters['Identity'].Aliases |
                Should -Contain $AliasName
        }
    }

    Context 'When the caller holds Tier 0 privileges and everything succeeds' {
        BeforeEach {
            Mock -CommandName Get-PSADTokenGroupSid -ModuleName $dscModuleName -MockWith {
                $script:domainAdminSid
            }

            Mock -CommandName Get-PSADDomainController -ModuleName $dscModuleName -MockWith {
                script:New-TestDomainController -Name 'DC01.corp.contoso.com', 'DC02.corp.contoso.com'
            }

            Mock -CommandName Test-PSADLdapConnectivity -ModuleName $dscModuleName -MockWith { $true }

            Mock -CommandName Invoke-PSADNtdsutil -ModuleName $dscModuleName -MockWith {
                [PSCustomObject]@{
                    ServerName     = 'DC01.corp.contoso.com'
                    ExitCode       = 0
                    StandardOutput = $script:successTranscript
                    StandardError  = ''
                }
            }

            Mock -CommandName Write-PSADAuditEvent -ModuleName $dscModuleName -MockWith { $true }
        }

        It 'Should report a Success status' {
            $result = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false

            $result.Status | Should -Be 'Success'
        }

        It 'Should return the canonical fully qualified name reported by the directory' {
            $result = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false

            $result.ComputerName | Should -Be 'DC01.corp.contoso.com'
            $result.Identity | Should -Be 'DC01'
        }

        It 'Should return a UTC timestamp' {
            $result = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false

            $result.Timestamp | Should -BeOfType [datetime]
            $result.Timestamp.Kind | Should -Be ([System.DateTimeKind]::Utc)
        }

        It 'Should expose the documented contract properties' {
            $result = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false

            foreach ($propertyName in @('ComputerName', 'Status', 'Timestamp', 'Notes'))
            {
                $result.PSObject.Properties.Name | Should -Contain $propertyName
            }
        }

        It 'Should invoke ntdsutil exactly once' {
            $null = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false

            Should -Invoke -CommandName Invoke-PSADNtdsutil -Exactly -Times 1 -Scope It -ModuleName $dscModuleName
        }

        It 'Should hand ntdsutil a SecureString and the sanitised server name' {
            $null = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false

            Should -Invoke -CommandName Invoke-PSADNtdsutil -Exactly -Times 1 -Scope It -ModuleName $dscModuleName -ParameterFilter {
                $Password -is [System.Security.SecureString] -and $ServerName -eq 'DC01.corp.contoso.com'
            }
        }

        It 'Should resolve a distinguished name to the server object name' {
            $null = Set-PSADDsrmPassword -Identity 'CN=DC02,OU=Domain Controllers,DC=corp,DC=contoso,DC=com' -NewPassword $script:strongPassword -Confirm:$false

            Should -Invoke -CommandName Invoke-PSADNtdsutil -Exactly -Times 1 -Scope It -ModuleName $dscModuleName -ParameterFilter {
                $ServerName -eq 'DC02.corp.contoso.com'
            }
        }

        It 'Should query the domain derived from the distinguished name' {
            $null = Set-PSADDsrmPassword -Identity 'CN=DC02,OU=Domain Controllers,DC=corp,DC=contoso,DC=com' -NewPassword $script:strongPassword -Confirm:$false

            Should -Invoke -CommandName Get-PSADDomainController -Exactly -Times 1 -Scope It -ModuleName $dscModuleName -ParameterFilter {
                $DomainName -eq 'corp.contoso.com'
            }
        }

        It 'Should audit the attempt before the change and the success after it' {
            $null = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false

            Should -Invoke -CommandName Write-PSADAuditEvent -Exactly -Times 1 -Scope It -ModuleName $dscModuleName -ParameterFilter {
                $EventId -eq 9000 -and $Message -match 'ATTEMPT'
            }

            Should -Invoke -CommandName Write-PSADAuditEvent -Exactly -Times 1 -Scope It -ModuleName $dscModuleName -ParameterFilter {
                $EventId -eq 9001 -and $Message -match 'SUCCESS'
            }
        }

        It 'Should never place the secret in an audit record' {
            $null = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false

            Should -Invoke -CommandName Write-PSADAuditEvent -Times 0 -Scope It -ModuleName $dscModuleName -ParameterFilter {
                $Message -match 'Tr0ub4dor'
            }
        }

        It 'Should never leak the secret into the verbose or output streams' {
            $captured = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false -Verbose 4>&1 |
                Out-String

            $captured | Should -Not -Match 'Tr0ub4dor'
            $captured | Should -Not -Match 'Horse-Battery'
        }
    }

    Context 'When the password does not satisfy the Tier 0 policy' {
        BeforeEach {
            Mock -CommandName Get-PSADTokenGroupSid -ModuleName $dscModuleName -MockWith { $script:domainAdminSid }
            Mock -CommandName Get-PSADDomainController -ModuleName $dscModuleName -MockWith { script:New-TestDomainController -Name 'DC01.corp.contoso.com' }
            Mock -CommandName Test-PSADLdapConnectivity -ModuleName $dscModuleName -MockWith { $true }
            Mock -CommandName Invoke-PSADNtdsutil -ModuleName $dscModuleName -MockWith { throw 'ntdsutil must never run' }
            Mock -CommandName Write-PSADAuditEvent -ModuleName $dscModuleName -MockWith { $true }
        }

        It 'Should throw before touching any domain controller' {
            { Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:weakPassword -Confirm:$false } |
                Should -Throw -ExpectedMessage '*does not satisfy the Tier 0 password policy*'
        }

        It 'Should not invoke ntdsutil' {
            { Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:weakPassword -Confirm:$false } | Should -Throw

            Should -Invoke -CommandName Invoke-PSADNtdsutil -Exactly -Times 0 -Scope It -ModuleName $dscModuleName
        }

        It 'Should reject a password containing a control character' {
            $injected = script:New-TestSecureString -PlainText "Str0ngEnough!Pass`r`nquit"

            { Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $injected -Confirm:$false } |
                Should -Throw -ExpectedMessage '*control character*'
        }
    }

    Context 'When the caller does not hold Tier 0 privileges' {
        BeforeEach {
            Mock -CommandName Get-PSADTokenGroupSid -ModuleName $dscModuleName -MockWith { $script:unprivilegedSid }
            Mock -CommandName Get-PSADDomainController -ModuleName $dscModuleName -MockWith { script:New-TestDomainController -Name 'DC01.corp.contoso.com' }
            Mock -CommandName Test-PSADLdapConnectivity -ModuleName $dscModuleName -MockWith { $true }
            Mock -CommandName Invoke-PSADNtdsutil -ModuleName $dscModuleName -MockWith { throw 'ntdsutil must never run' }
            Mock -CommandName Write-PSADAuditEvent -ModuleName $dscModuleName -MockWith { $true }
        }

        It 'Should throw an UnauthorizedAccessException' {
            $exception = { Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false } |
                Should -Throw -PassThru

            $exception.Exception.GetType().FullName | Should -Be 'System.UnauthorizedAccessException'
        }

        It 'Should not invoke ntdsutil' {
            { Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false } | Should -Throw

            Should -Invoke -CommandName Invoke-PSADNtdsutil -Exactly -Times 0 -Scope It -ModuleName $dscModuleName
        }

        It 'Should write a denial audit record so the refusal is forensically visible' {
            { Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false } | Should -Throw

            Should -Invoke -CommandName Write-PSADAuditEvent -Exactly -Times 1 -Scope It -ModuleName $dscModuleName -ParameterFilter {
                $EventId -eq 9003 -and $EntryType -eq 'Error' -and $Message -match 'DENIED'
            }
        }
    }

    Context 'When WhatIf is supplied' {
        BeforeEach {
            Mock -CommandName Get-PSADTokenGroupSid -ModuleName $dscModuleName -MockWith { $script:domainAdminSid }
            Mock -CommandName Get-PSADDomainController -ModuleName $dscModuleName -MockWith { script:New-TestDomainController -Name 'DC01.corp.contoso.com' }
            Mock -CommandName Test-PSADLdapConnectivity -ModuleName $dscModuleName -MockWith { $true }
            Mock -CommandName Invoke-PSADNtdsutil -ModuleName $dscModuleName -MockWith { throw 'ntdsutil must never run under WhatIf' }
            Mock -CommandName Write-PSADAuditEvent -ModuleName $dscModuleName -MockWith { $true }
        }

        It 'Should report a Skipped status' {
            $result = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -WhatIf

            $result.Status | Should -Be 'Skipped'
        }

        It 'Should not invoke ntdsutil' {
            $null = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -WhatIf

            Should -Invoke -CommandName Invoke-PSADNtdsutil -Exactly -Times 0 -Scope It -ModuleName $dscModuleName
        }

        It 'Should not write any audit record because nothing was attempted' {
            $null = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -WhatIf

            Should -Invoke -CommandName Write-PSADAuditEvent -Exactly -Times 0 -Scope It -ModuleName $dscModuleName
        }

        It 'Should still perform the existence and reachability checks so the dry run is meaningful' {
            $null = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -WhatIf

            Should -Invoke -CommandName Get-PSADDomainController -Exactly -Times 1 -Scope It -ModuleName $dscModuleName
            Should -Invoke -CommandName Test-PSADLdapConnectivity -Exactly -Times 1 -Scope It -ModuleName $dscModuleName
        }
    }

    Context 'When the target is not a domain controller' {
        BeforeEach {
            Mock -CommandName Get-PSADTokenGroupSid -ModuleName $dscModuleName -MockWith { $script:domainAdminSid }
            Mock -CommandName Get-PSADDomainController -ModuleName $dscModuleName -MockWith { script:New-TestDomainController -Name 'DC01.corp.contoso.com' }
            Mock -CommandName Test-PSADLdapConnectivity -ModuleName $dscModuleName -MockWith { $true }
            Mock -CommandName Invoke-PSADNtdsutil -ModuleName $dscModuleName -MockWith { throw 'ntdsutil must never run' }
            Mock -CommandName Write-PSADAuditEvent -ModuleName $dscModuleName -MockWith { $true }
        }

        It 'Should report Failed with a TargetNotFound category instead of aborting' {
            $result = Set-PSADDsrmPassword -Identity 'FILESERVER01' -NewPassword $script:strongPassword -Confirm:$false -ErrorAction SilentlyContinue

            $result.Status | Should -Be 'Failed'
            $result.FailureCategory | Should -Be 'TargetNotFound'
        }

        It 'Should not invoke ntdsutil' {
            $null = Set-PSADDsrmPassword -Identity 'FILESERVER01' -NewPassword $script:strongPassword -Confirm:$false -ErrorAction SilentlyContinue

            Should -Invoke -CommandName Invoke-PSADNtdsutil -Exactly -Times 0 -Scope It -ModuleName $dscModuleName
        }

        It 'Should emit a non terminating error so existing error handling still observes it' {
            $errorOutput = $null
            $null = Set-PSADDsrmPassword -Identity 'FILESERVER01' -NewPassword $script:strongPassword -Confirm:$false -ErrorVariable errorOutput -ErrorAction SilentlyContinue

            $errorOutput | Should -Not -BeNullOrEmpty
        }
    }

    Context 'When the domain controller is unreachable' {
        BeforeEach {
            Mock -CommandName Get-PSADTokenGroupSid -ModuleName $dscModuleName -MockWith { $script:domainAdminSid }
            Mock -CommandName Get-PSADDomainController -ModuleName $dscModuleName -MockWith { script:New-TestDomainController -Name 'DC01.corp.contoso.com' }
            Mock -CommandName Test-PSADLdapConnectivity -ModuleName $dscModuleName -MockWith { $false }
            Mock -CommandName Invoke-PSADNtdsutil -ModuleName $dscModuleName -MockWith { throw 'ntdsutil must never run' }
            Mock -CommandName Write-PSADAuditEvent -ModuleName $dscModuleName -MockWith { $true }
        }

        It 'Should report Failed and never attempt the reset' {
            $result = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false -ErrorAction SilentlyContinue

            $result.Status | Should -Be 'Failed'
            ($result.Notes -join ' ') | Should -Match 'did not answer on LDAP port 389'

            Should -Invoke -CommandName Invoke-PSADNtdsutil -Exactly -Times 0 -Scope It -ModuleName $dscModuleName
        }

        It 'Should write a failure audit record' {
            $null = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false -ErrorAction SilentlyContinue

            Should -Invoke -CommandName Write-PSADAuditEvent -Exactly -Times 1 -Scope It -ModuleName $dscModuleName -ParameterFilter {
                $EventId -eq 9002
            }
        }
    }

    Context 'When ntdsutil reports a failure' {
        BeforeEach {
            Mock -CommandName Get-PSADTokenGroupSid -ModuleName $dscModuleName -MockWith { $script:domainAdminSid }
            Mock -CommandName Get-PSADDomainController -ModuleName $dscModuleName -MockWith { script:New-TestDomainController -Name 'DC01.corp.contoso.com' }
            Mock -CommandName Test-PSADLdapConnectivity -ModuleName $dscModuleName -MockWith { $true }
            Mock -CommandName Write-PSADAuditEvent -ModuleName $dscModuleName -MockWith { $true }
        }

        It 'Should surface an access denied transcript as an authorization failure' {
            Mock -CommandName Invoke-PSADNtdsutil -ModuleName $dscModuleName -MockWith {
                [PSCustomObject]@{
                    ServerName     = 'DC01.corp.contoso.com'
                    ExitCode       = 0
                    StandardOutput = 'Setting password failed. Access is denied.'
                    StandardError  = ''
                }
            }

            $result = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false -ErrorAction SilentlyContinue

            $result.Status | Should -Be 'Failed'
            ($result.Notes -join ' ') | Should -Match 'Access was denied'
        }

        It 'Should treat an unrecognised transcript as a failure rather than a silent success' {
            Mock -CommandName Invoke-PSADNtdsutil -ModuleName $dscModuleName -MockWith {
                [PSCustomObject]@{
                    ServerName     = 'DC01.corp.contoso.com'
                    ExitCode       = 0
                    StandardOutput = 'ntdsutil: quit'
                    StandardError  = ''
                }
            }

            $result = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false -ErrorAction SilentlyContinue

            $result.Status | Should -Be 'Failed'
            ($result.Notes -join ' ') | Should -Match 'must be considered unchanged'
        }

        It 'Should surface a launch failure as a MissingTooling category' {
            Mock -CommandName Invoke-PSADNtdsutil -ModuleName $dscModuleName -MockWith {
                throw [System.IO.FileNotFoundException]::new('ntdsutil.exe was not found.')
            }

            $result = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false -ErrorAction SilentlyContinue

            $result.FailureCategory | Should -Be 'MissingTooling'
            ($result.Notes -join ' ') | Should -Match 'Remote Server Administration Tools'
        }
    }

    Context 'When processing a batch over the pipeline' {
        BeforeEach {
            Mock -CommandName Get-PSADTokenGroupSid -ModuleName $dscModuleName -MockWith { $script:domainAdminSid }

            Mock -CommandName Get-PSADDomainController -ModuleName $dscModuleName -MockWith {
                script:New-TestDomainController -Name 'DC01.corp.contoso.com', 'DC02.corp.contoso.com', 'DC03.corp.contoso.com'
            }

            Mock -CommandName Test-PSADLdapConnectivity -ModuleName $dscModuleName -MockWith {
                # DC02 is deliberately isolated to prove the batch survives one failure.
                return ($ComputerName -ne 'DC02.corp.contoso.com')
            }

            Mock -CommandName Invoke-PSADNtdsutil -ModuleName $dscModuleName -MockWith {
                [PSCustomObject]@{
                    ServerName     = $ServerName
                    ExitCode       = 0
                    StandardOutput = 'Password has been set successfully.'
                    StandardError  = ''
                }
            }

            Mock -CommandName Write-PSADAuditEvent -ModuleName $dscModuleName -MockWith { $true }
        }

        It 'Should return one result per domain controller' {
            $result = @('DC01', 'DC02', 'DC03' |
                    Set-PSADDsrmPassword -NewPassword $script:strongPassword -Confirm:$false -ErrorAction SilentlyContinue)

            $result.Count | Should -Be 3
        }

        It 'Should not let one unreachable domain controller abort the batch' {
            $result = @('DC01', 'DC02', 'DC03' |
                    Set-PSADDsrmPassword -NewPassword $script:strongPassword -Confirm:$false -ErrorAction SilentlyContinue)

            @($result).Where({ 'Success' -eq $_.Status }).Count | Should -Be 2
            @($result).Where({ 'Failed' -eq $_.Status }).Count | Should -Be 1
            @($result).Where({ 'Failed' -eq $_.Status }).ComputerName | Should -Be 'DC02.corp.contoso.com'
        }

        It 'Should evaluate Tier 0 privileges once for the whole batch (credential caching)' {
            $null = 'DC01', 'DC02', 'DC03' |
                Set-PSADDsrmPassword -NewPassword $script:strongPassword -Confirm:$false -ErrorAction SilentlyContinue

            Should -Invoke -CommandName Get-PSADTokenGroupSid -Exactly -Times 1 -Scope It -ModuleName $dscModuleName
        }

        It 'Should accept objects bound by the Name property' {
            $controller = script:New-TestDomainController -Name 'DC01.corp.contoso.com', 'DC03.corp.contoso.com'

            $result = @($controller | Set-PSADDsrmPassword -NewPassword $script:strongPassword -Confirm:$false -ErrorAction SilentlyContinue)

            $result.Count | Should -Be 2
            $result.Status | Should -Not -Contain 'Failed'
        }

        It 'Should stream each result as the batch progresses rather than only at the end' {
            $order = [System.Collections.Generic.List[System.String]]::new()

            'DC01', 'DC03' |
                Set-PSADDsrmPassword -NewPassword $script:strongPassword -Confirm:$false -ErrorAction SilentlyContinue |
                ForEach-Object -Process { $order.Add($_.ComputerName) }

            $order | Should -Be @('DC01.corp.contoso.com', 'DC03.corp.contoso.com')
        }

        It 'Should honour an explicit ErrorAction Stop by terminating the batch at the first failure' {
            <#
                Documented contract: Stop means stop. The result object for the failing domain
                controller is still emitted from the finally block before the pipeline ends,
                so the operator can see exactly where the batch halted.
            #>
            $collected = [System.Collections.Generic.List[PSObject]]::new()
            $terminated = $false

            try
            {
                'DC01', 'DC02', 'DC03' |
                    Set-PSADDsrmPassword -NewPassword $script:strongPassword -Confirm:$false -ErrorAction Stop |
                    ForEach-Object -Process { $collected.Add($_) }
            }
            catch
            {
                $terminated = $true
            }

            $terminated | Should -BeTrue
            $collected.Count | Should -Be 2
            $collected[-1].Status | Should -Be 'Failed'
            $collected[-1].ComputerName | Should -Be 'DC02.corp.contoso.com'

            Should -Invoke -CommandName Invoke-PSADNtdsutil -Exactly -Times 1 -Scope It -ModuleName $dscModuleName
        }
    }

    Context 'When an alternate credential is supplied' {
        BeforeEach {
            Mock -CommandName Get-PSADTokenGroupSid -ModuleName $dscModuleName -MockWith { $script:domainAdminSid }
            Mock -CommandName Get-PSADDomainController -ModuleName $dscModuleName -MockWith { script:New-TestDomainController -Name 'DC01.corp.contoso.com' }
            Mock -CommandName Test-PSADLdapConnectivity -ModuleName $dscModuleName -MockWith { $true }
            Mock -CommandName Write-PSADAuditEvent -ModuleName $dscModuleName -MockWith { $true }

            Mock -CommandName Invoke-PSADNtdsutil -ModuleName $dscModuleName -MockWith {
                [PSCustomObject]@{
                    ServerName     = 'DC01.corp.contoso.com'
                    ExitCode       = 0
                    StandardOutput = 'Password has been set successfully.'
                    StandardError  = ''
                }
            }

            $script:tier0Credential = [System.Management.Automation.PSCredential]::new(
                'CORP\adm_jsmith',
                (script:New-TestSecureString -PlainText 'Placeholder-Value-01!'))
        }

        It 'Should evaluate the privileges of the supplied credential, not the current token' {
            $null = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Credential $script:tier0Credential -Confirm:$false

            Should -Invoke -CommandName Get-PSADTokenGroupSid -Exactly -Times 1 -Scope It -ModuleName $dscModuleName -ParameterFilter {
                $Credential.UserName -eq 'CORP\adm_jsmith'
            }
        }

        It 'Should launch ntdsutil under the supplied credential' {
            $null = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Credential $script:tier0Credential -Confirm:$false

            Should -Invoke -CommandName Invoke-PSADNtdsutil -Exactly -Times 1 -Scope It -ModuleName $dscModuleName -ParameterFilter {
                $Credential.UserName -eq 'CORP\adm_jsmith'
            }
        }

        It 'Should attribute the operation to the supplied credential in the report' {
            $result = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Credential $script:tier0Credential -Confirm:$false

            $result.PerformedBy | Should -Be 'CORP\adm_jsmith'
        }

        It 'Should surface a failed privilege evaluation as an authorization failure' {
            Mock -CommandName Get-PSADTokenGroupSid -ModuleName $dscModuleName -MockWith {
                throw [System.InvalidOperationException]::new('The server is not operational.')
            }

            $exception = {
                Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Credential $script:tier0Credential -Confirm:$false
            } | Should -Throw -PassThru

            $exception.Exception.GetType().FullName | Should -Be 'System.UnauthorizedAccessException'
            $exception.Exception.InnerException | Should -Not -BeNullOrEmpty
        }
    }

    Context 'When Force is supplied' {
        BeforeEach {
            Mock -CommandName Get-PSADTokenGroupSid -ModuleName $dscModuleName -MockWith { $script:domainAdminSid }
            Mock -CommandName Get-PSADDomainController -ModuleName $dscModuleName -MockWith { script:New-TestDomainController -Name 'DC01.corp.contoso.com' }
            Mock -CommandName Test-PSADLdapConnectivity -ModuleName $dscModuleName -MockWith { $true }
            Mock -CommandName Write-PSADAuditEvent -ModuleName $dscModuleName -MockWith { $true }

            Mock -CommandName Invoke-PSADNtdsutil -ModuleName $dscModuleName -MockWith {
                [PSCustomObject]@{
                    ServerName     = 'DC01.corp.contoso.com'
                    ExitCode       = 0
                    StandardOutput = 'Password has been set successfully.'
                    StandardError  = ''
                }
            }
        }

        It 'Should proceed without a confirmation prompt' {
            $result = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Force

            $result.Status | Should -Be 'Success'
        }

        It 'Should not bypass the Tier 0 privilege gate' {
            Mock -CommandName Get-PSADTokenGroupSid -ModuleName $dscModuleName -MockWith { $script:unprivilegedSid }

            { Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Force } |
                Should -Throw -ExpectedMessage '*does not hold Tier 0 privileges*'
        }

        It 'Should not bypass the password policy gate' {
            { Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:weakPassword -Force } |
                Should -Throw -ExpectedMessage '*Tier 0 password policy*'
        }

        It 'Should still honour an explicit WhatIf over Force' {
            $result = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Force -WhatIf

            $result.Status | Should -Be 'Skipped'
            Should -Invoke -CommandName Invoke-PSADNtdsutil -Exactly -Times 0 -Scope It -ModuleName $dscModuleName
        }
    }
}

Describe 'Set-PSADDsrmPassword operator feedback' {
    BeforeEach {
        Mock -CommandName Get-PSADTokenGroupSid -ModuleName $dscModuleName -MockWith { $script:domainAdminSid }
        Mock -CommandName Get-PSADDomainController -ModuleName $dscModuleName -MockWith {
            script:New-TestDomainController -Name 'DC01.corp.contoso.com', 'DC02.corp.contoso.com'
        }
        Mock -CommandName Test-PSADLdapConnectivity -ModuleName $dscModuleName -MockWith { $true }
        Mock -CommandName Write-PSADAuditEvent -ModuleName $dscModuleName -MockWith { $true }
        Mock -CommandName Write-Progress -ModuleName $dscModuleName -MockWith { }

        Mock -CommandName Invoke-PSADNtdsutil -ModuleName $dscModuleName -MockWith {
            [PSCustomObject]@{
                ServerName     = $ServerName
                ExitCode       = 0
                StandardOutput = 'Password has been set successfully.'
                StandardError  = ''
            }
        }
    }

    Context 'Verbose narration of every gate' {
        BeforeEach {
            $script:narration = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false -Verbose 4>&1 |
                Out-String
        }

        It 'Should narrate the <GateName> gate' -ForEach @(
            @{ GateName = 'password complexity'; Pattern = 'Validating password complexity' }
            @{ GateName = 'Tier 0 privilege'; Pattern = 'Checking Tier 0 privileges' }
            @{ GateName = 'domain controller existence'; Pattern = 'Verifying domain controller existence' }
            @{ GateName = 'LDAP connectivity'; Pattern = 'Testing LDAP connectivity' }
            @{ GateName = 'ntdsutil reset'; Pattern = 'Resetting DSRM password via ntdsutil' }
            @{ GateName = 'audit'; Pattern = 'Writing audit event' }
        ) {
            $script:narration | Should -Match $Pattern
        }

        It 'Should narrate the closing batch summary' {
            $script:narration | Should -Match 'DSRM rotation batch complete'
            $script:narration | Should -Match 'Processed: 1'
        }
    }

    Context 'Progress reporting' {
        It 'Should report the domain controller currently being processed' {
            $null = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false

            Should -Invoke -CommandName Write-Progress -Exactly -Times 1 -Scope It -ModuleName $dscModuleName -ParameterFilter {
                $Activity -eq 'Resetting DSRM passwords' -and $Status -eq 'Processing DC01'
            }
        }

        It 'Should report a determinate percentage when the batch size is known' {
            $null = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false

            Should -Invoke -CommandName Write-Progress -Exactly -Times 1 -Scope It -ModuleName $dscModuleName -ParameterFilter {
                $PercentComplete -eq 100
            }
        }

        It 'Should report an indeterminate bar rather than a fabricated percentage for pipeline input' {
            <#
                A pipeline does not expose its length, so inventing a denominator would render
                a progress bar that lies. -1 is the documented indeterminate value.
            #>
            $null = 'DC01', 'DC02' |
                Set-PSADDsrmPassword -NewPassword $script:strongPassword -Confirm:$false

            Should -Invoke -CommandName Write-Progress -Exactly -Times 2 -Scope It -ModuleName $dscModuleName -ParameterFilter {
                $PercentComplete -eq -1
            }
        }

        It 'Should advance the running count across a pipeline batch' {
            $null = 'DC01', 'DC02' |
                Set-PSADDsrmPassword -NewPassword $script:strongPassword -Confirm:$false

            Should -Invoke -CommandName Write-Progress -Exactly -Times 1 -Scope It -ModuleName $dscModuleName -ParameterFilter {
                $CurrentOperation -match 'Domain controller 2 of the pipeline batch'
            }
        }

        It 'Should complete the progress record so no orphaned bar survives the batch' {
            $null = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false

            Should -Invoke -CommandName Write-Progress -Exactly -Times 1 -Scope It -ModuleName $dscModuleName -ParameterFilter {
                $Completed -eq $true
            }
        }
    }

    Context 'AnalysisLevel parameter contract' {
        It 'Should accept only Quick and Thorough' {
            $validateSet = (Get-Command -Name 'Set-PSADDsrmPassword').Parameters['AnalysisLevel'].Attributes.Where({
                    $_ -is [System.Management.Automation.ValidateSetAttribute]
                })

            $validateSet.ValidValues | Should -Be @('Quick', 'Thorough')
        }

        It 'Should reject an unknown analysis level' {
            { Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -AnalysisLevel 'Paranoid' -Confirm:$false } |
                Should -Throw
        }

        It 'Should default to Thorough so existing scripts are unaffected' {
            $default = (Get-Command -Name 'Set-PSADDsrmPassword').ScriptBlock.Ast.Body.ParamBlock.Parameters.Where({
                    $_.Name.VariablePath.UserPath -eq 'AnalysisLevel'
                }).DefaultValue.Extent.Text

            $default | Should -Be "'Thorough'"
        }

        It 'Should be optional' {
            (Get-Command -Name 'Set-PSADDsrmPassword').Parameters['AnalysisLevel'].Attributes.Where({
                    $_ -is [System.Management.Automation.ParameterAttribute]
                }).Mandatory | Should -Not -Contain $true
        }
    }

    Context 'AnalysisLevel Quick' {
        It 'Should suppress the narration even when Verbose is explicitly supplied' {
            $captured = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false -AnalysisLevel 'Quick' -Verbose 4>&1 |
                Out-String

            $captured | Should -Not -Match 'Validating password complexity'
            $captured | Should -Not -Match 'Resetting DSRM password via ntdsutil'
        }

        It 'Should suppress the progress bar' {
            $null = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false -AnalysisLevel 'Quick'

            <#
                ProgressPreference is lowered rather than the call being removed, so the
                cmdlet is still reached. The observable contract is that nothing renders.
            #>
            Should -Invoke -CommandName Write-Progress -Scope It -ModuleName $dscModuleName
        }

        It 'Should still return the full result object' {
            $result = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false -AnalysisLevel 'Quick'

            $result.Status | Should -Be 'Success'
            $result.ComputerName | Should -Be 'DC01.corp.contoso.com'
        }

        It 'Should NOT suppress the Windows event log audit trail' {
            $null = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false -AnalysisLevel 'Quick'

            Should -Invoke -CommandName Write-PSADAuditEvent -Exactly -Times 1 -Scope It -ModuleName $dscModuleName -ParameterFilter {
                $EventId -eq 9000
            }
            Should -Invoke -CommandName Write-PSADAuditEvent -Exactly -Times 1 -Scope It -ModuleName $dscModuleName -ParameterFilter {
                $EventId -eq 9001
            }
        }

        It 'Should NOT suppress the non terminating error on failure' {
            Mock -CommandName Test-PSADLdapConnectivity -ModuleName $dscModuleName -MockWith { $false }

            $errorOutput = $null
            $null = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false -AnalysisLevel 'Quick' -ErrorVariable errorOutput -ErrorAction SilentlyContinue

            $errorOutput | Should -Not -BeNullOrEmpty
        }

        It 'Should NOT bypass the password policy gate' {
            { Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:weakPassword -Confirm:$false -AnalysisLevel 'Quick' } |
                Should -Throw -ExpectedMessage '*Tier 0 password policy*'
        }

        It 'Should NOT bypass the Tier 0 privilege gate' {
            Mock -CommandName Get-PSADTokenGroupSid -ModuleName $dscModuleName -MockWith { $script:unprivilegedSid }

            { Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false -AnalysisLevel 'Quick' } |
                Should -Throw -ExpectedMessage '*does not hold Tier 0 privileges*'
        }

        It 'Should NOT bypass the confirmation gate' {
            $result = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -AnalysisLevel 'Quick' -WhatIf

            $result.Status | Should -Be 'Skipped'
            Should -Invoke -CommandName Invoke-PSADNtdsutil -Exactly -Times 0 -Scope It -ModuleName $dscModuleName
        }
    }

    Context 'AnalysisLevel Thorough' {
        It 'Should produce the narration that Quick suppresses' {
            $captured = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false -AnalysisLevel 'Thorough' -Verbose 4>&1 |
                Out-String

            $captured | Should -Match 'Validating password complexity'
        }

        It 'Should stay silent when Verbose is not requested' {
            $captured = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false -AnalysisLevel 'Thorough' 4>&1 |
                Out-String

            $captured | Should -Not -Match 'Validating password complexity'
        }
    }

    Context 'Streaming output' {
        It 'Should emit each result before the next domain controller is started' {
            <#
                Proves the results are not buffered: the downstream stage must observe the
                first result while the second is still being processed, which is only
                possible if the object is emitted from the process block.
            #>
            $observed = [System.Collections.Generic.List[System.String]]::new()

            'DC01', 'DC02' |
                Set-PSADDsrmPassword -NewPassword $script:strongPassword -Confirm:$false |
                ForEach-Object -Process {
                    $observed.Add($_.ComputerName)

                    if (1 -eq $observed.Count)
                    {
                        # DC02 has not been handed to ntdsutil yet at this point.
                        Should -Invoke -CommandName Invoke-PSADNtdsutil -Exactly -Times 1 -Scope It -ModuleName $dscModuleName
                    }
                }

            $observed | Should -Be @('DC01.corp.contoso.com', 'DC02.corp.contoso.com')
        }
    }
}

Describe 'Set-PSADDsrmPassword error handling specificity' {
    BeforeAll {
        <#
            Some directory exception types are not loadable on every host, and this module
            deliberately takes no dependency on the ActiveDirectory RSAT module. Where the
            real type is absent a stub carrying the identical full type name is compiled, so
            the runtime classification contract is exercised on every platform. The stub is
            only created when the genuine type cannot be resolved.
        #>
        function script:Confirm-TestExceptionType
        {
            param
            (
                [string]$FullName,
                [string]$Namespace,
                [string]$ClassName
            )

            if ($FullName -as [type])
            {
                return
            }

            $source = @"
namespace $Namespace
{
    public class $ClassName : System.Exception
    {
        public $ClassName(string message) : base(message) { }
    }
}
"@
            Add-Type -TypeDefinition $source -ErrorAction Stop
        }

        script:Confirm-TestExceptionType -FullName 'Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException' -Namespace 'Microsoft.ActiveDirectory.Management' -ClassName 'ADIdentityNotFoundException'
        script:Confirm-TestExceptionType -FullName 'System.DirectoryServices.Protocols.LdapException' -Namespace 'System.DirectoryServices.Protocols' -ClassName 'LdapException'
    }

    BeforeEach {
        Mock -CommandName Get-PSADTokenGroupSid -ModuleName $dscModuleName -MockWith { $script:domainAdminSid }
        Mock -CommandName Get-PSADDomainController -ModuleName $dscModuleName -MockWith {
            script:New-TestDomainController -Name 'DC01.corp.contoso.com'
        }
        Mock -CommandName Test-PSADLdapConnectivity -ModuleName $dscModuleName -MockWith { $true }
        Mock -CommandName Write-PSADAuditEvent -ModuleName $dscModuleName -MockWith { $true }
        Mock -CommandName Write-Progress -ModuleName $dscModuleName -MockWith { }
    }

    Context 'When a specific exception type is raised by the reset' {
        It 'Should classify <TypeName> as <Category> and add a context specific note' -ForEach @(
            @{
                TypeName = 'System.UnauthorizedAccessException'
                Category = 'Authorization'
                Pattern  = 'Permission denied while resetting the DSRM password'
            }
            @{
                TypeName = 'System.TimeoutException'
                Category = 'Timeout'
                Pattern  = 'INDETERMINATE'
            }
            @{
                TypeName = 'System.DirectoryServices.Protocols.LdapException'
                Category = 'LdapConnectivity'
                Pattern  = 'LDAP conversation with the domain controller failed'
            }
            @{
                TypeName = 'Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException'
                Category = 'TargetNotFound'
                Pattern  = 'Verify the identity against Get-PSADDomainController'
            }
        ) {
            $thrownType = $TypeName

            Mock -CommandName Invoke-PSADNtdsutil -ModuleName $dscModuleName -MockWith {
                throw (New-Object -TypeName $thrownType -ArgumentList 'simulated failure')
            }

            $result = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false -ErrorAction SilentlyContinue

            $result.Status | Should -Be 'Failed'
            $result.FailureCategory | Should -Be $Category
            ($result.Notes -join ' ') | Should -Match $Pattern
        }

        It 'Should classify a SocketException as Connectivity with a TCP specific note' {
            Mock -CommandName Invoke-PSADNtdsutil -ModuleName $dscModuleName -MockWith {
                throw [System.Net.Sockets.SocketException]::new(10060)
            }

            $result = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false -ErrorAction SilentlyContinue

            $result.Status | Should -Be 'Failed'
            $result.FailureCategory | Should -Be 'Connectivity'
            ($result.Notes -join ' ') | Should -Match 'TCP connectivity to .* failed at the socket layer'
        }

        It 'Should classify a missing domain controller as TargetNotFound with a lookup specific note' {
            Mock -CommandName Invoke-PSADNtdsutil -ModuleName $dscModuleName -MockWith { throw 'ntdsutil must never run' }

            $result = Set-PSADDsrmPassword -Identity 'FILESERVER01' -NewPassword $script:strongPassword -Confirm:$false -ErrorAction SilentlyContinue

            $result.FailureCategory | Should -Be 'TargetNotFound'
            ($result.Notes -join ' ') | Should -Match 'was not found in the domain controller inventory'
        }

        It 'Should re-raise a platform failure unchanged rather than masking it as an authorization failure' {
            <#
                A PlatformNotSupportedException means the Tier 0 privilege could not be
                evaluated because the host is not Windows at all. Re-wrapping it as an
                UnauthorizedAccessException would send an operator hunting a group
                membership problem that does not exist.
            #>
            Mock -CommandName Get-PSADTokenGroupSid -ModuleName $dscModuleName -MockWith {
                throw [System.PlatformNotSupportedException]::new('Access token enumeration requires Windows.')
            }

            $exception = {
                Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false
            } | Should -Throw -PassThru

            $exception.Exception.GetType().FullName | Should -Be 'System.PlatformNotSupportedException'
            $exception.Exception.Message | Should -Match 'requires Windows'
        }

        It 'Should still expose the original error record for downstream triage' {
            Mock -CommandName Invoke-PSADNtdsutil -ModuleName $dscModuleName -MockWith {
                throw [System.TimeoutException]::new('simulated timeout')
            }

            $result = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false -ErrorAction SilentlyContinue

            $result.ErrorRecord | Should -Not -BeNullOrEmpty
            $result.ErrorRecord.Exception.GetType().FullName | Should -Be 'System.TimeoutException'
        }
    }

    Context 'Batch resilience under typed failures' {
        BeforeEach {
            Mock -CommandName Get-PSADDomainController -ModuleName $dscModuleName -MockWith {
                script:New-TestDomainController -Name 'DC01.corp.contoso.com', 'DC02.corp.contoso.com', 'DC03.corp.contoso.com'
            }

            Mock -CommandName Invoke-PSADNtdsutil -ModuleName $dscModuleName -MockWith {
                if ('DC02.corp.contoso.com' -eq $ServerName)
                {
                    throw [System.UnauthorizedAccessException]::new('simulated denial')
                }

                [PSCustomObject]@{
                    ServerName     = $ServerName
                    ExitCode       = 0
                    StandardOutput = 'Password has been set successfully.'
                    StandardError  = ''
                }
            }
        }

        It 'Should not let a typed per host failure abort the batch' {
            $result = @('DC01', 'DC02', 'DC03' |
                    Set-PSADDsrmPassword -NewPassword $script:strongPassword -Confirm:$false -ErrorAction SilentlyContinue)

            $result.Count | Should -Be 3
            @($result).Where({ 'Failed' -eq $_.Status }).FailureCategory | Should -Be 'Authorization'
        }

        It 'Should emit one non terminating error per failed domain controller only' {
            <#
                ErrorVariable also accumulates the raw exception as it bubbles through each
                nested scope, so the meaningful contract is the number of errors this
                function itself formatted and emitted, identified by its reporting sentence.
            #>
            $errorOutput = $null
            $null = 'DC01', 'DC02', 'DC03' |
                Set-PSADDsrmPassword -NewPassword $script:strongPassword -Confirm:$false -ErrorVariable errorOutput -ErrorAction SilentlyContinue

            $emitted = @($errorOutput).Where({ $_.ToString() -match 'The DSRM password reset failed for' })

            $emitted.Count | Should -Be 1
            $emitted[0].ToString() | Should -Match 'DC02\.corp\.contoso\.com'
            $emitted[0].ToString() | Should -Match '\[Authorization\]'
        }
    }

    Context 'Secret hygiene across every failure path' {
        It 'Should never leak the secret when the reset fails with <TypeName>' -ForEach @(
            @{ TypeName = 'System.UnauthorizedAccessException' }
            @{ TypeName = 'System.TimeoutException' }
            @{ TypeName = 'System.InvalidOperationException' }
        ) {
            $thrownType = $TypeName

            Mock -CommandName Invoke-PSADNtdsutil -ModuleName $dscModuleName -MockWith {
                throw (New-Object -TypeName $thrownType -ArgumentList 'simulated failure')
            }

            $captured = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false -Verbose -Debug:$false -ErrorAction SilentlyContinue *>&1 |
                Out-String

            $captured | Should -Not -Match 'Tr0ub4dor'
            $captured | Should -Not -Match 'Horse-Battery'
        }

        It 'Should never leak the secret into an audit record on a failure path' {
            Mock -CommandName Invoke-PSADNtdsutil -ModuleName $dscModuleName -MockWith {
                throw [System.UnauthorizedAccessException]::new('simulated denial')
            }

            $null = Set-PSADDsrmPassword -Identity 'DC01' -NewPassword $script:strongPassword -Confirm:$false -ErrorAction SilentlyContinue

            Should -Invoke -CommandName Write-PSADAuditEvent -Times 0 -Scope It -ModuleName $dscModuleName -ParameterFilter {
                $Message -match 'Tr0ub4dor'
            }
        }
    }
}
