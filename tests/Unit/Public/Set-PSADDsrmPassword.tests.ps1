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
