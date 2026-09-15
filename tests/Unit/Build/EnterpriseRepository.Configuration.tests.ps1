<#
    .SYNOPSIS
        Unit tests for the configuration and credential helpers backing the Invoke-Build
        task 'Publish_Module_To_EnterpriseRepository'.

    .DESCRIPTION
        The helpers live in ./.build/EnterpriseRepository.Configuration.ps1 and are
        dot-sourced here directly, which is possible because that file contains no
        Invoke-Build 'task' statement. No network, no SMB share and no real credential are
        involved.
#>

BeforeAll {
    $script:projectPath = "$($PSScriptRoot)/../../.." | Convert-Path

    $script:helperPath = Join-Path -Path $script:projectPath -ChildPath '.build' |
        Join-Path -ChildPath 'EnterpriseRepository.Configuration.ps1'

    . $script:helperPath

    <#
        A stub keeps the SecretManagement code path testable on an agent where the module
        is not installed. When the real module is present it is simply shadowed.
    #>
    if (-not (Get-Command -Name 'Get-Secret' -ErrorAction SilentlyContinue))
    {
        function Get-Secret
        {
            [CmdletBinding()]
            param
            (
                [Parameter()]
                [System.String]
                $Name,

                [Parameter()]
                [System.String]
                $Vault
            )
        }
    }

    $script:managedEnvironmentVariable = @(
        'ENTERPRISE_REPO_SMB_SHARE'
        'ENTERPRISE_REPO_CREDENTIAL'
        'ENTERPRISE_REPO_VAULT'
        'ENTERPRISE_REPO_USERNAME'
        'ENTERPRISE_REPO_PASSWORD'
        'ENTERPRISE_REPO_MODULE_PATH'
        'ENTERPRISE_REPO_WHATIF'
    )

    # Snapshot so a developer workstation configuration is never mutated by the tests.
    $script:environmentSnapshot = @{}

    foreach ($name in $script:managedEnvironmentVariable)
    {
        $script:environmentSnapshot[$name] = [System.Environment]::GetEnvironmentVariable($name)

        Remove-Item -Path "env:$name" -ErrorAction SilentlyContinue
    }

    <#
        A throw-away credential used to prove the parameter path. It is deliberately not a
        real identity: 'CORP\adm_jsmith' is a placeholder and the passphrase is a literal
        used only in memory by these tests.
    #>
    $script:parameterCredential = [System.Management.Automation.PSCredential]::new(
        'CORP\adm_jsmith',
        (ConvertTo-SecureString -String 'Parameter-Only-Unit-Test' -AsPlainText -Force)
    )
}

AfterAll {
    foreach ($name in $script:managedEnvironmentVariable)
    {
        Remove-Item -Path "env:$name" -ErrorAction SilentlyContinue

        if (-not [string]::IsNullOrEmpty($script:environmentSnapshot[$name]))
        {
            Set-Item -Path "env:$name" -Value $script:environmentSnapshot[$name]
        }
    }
}

Describe 'Import-EnterpriseRepositoryEnvFile' {
    AfterEach {
        foreach ($name in $script:managedEnvironmentVariable)
        {
            Remove-Item -Path "env:$name" -ErrorAction SilentlyContinue
        }
    }

    Context 'When the configuration file does not exist' {
        It 'Should return nothing and not throw' {
            $missingPath = Join-Path -Path $TestDrive -ChildPath 'absent.env'

            Import-EnterpriseRepositoryEnvFile -Path $missingPath | Should -BeNullOrEmpty
        }
    }

    Context 'When the configuration file contains valid entries' {
        BeforeEach {
            $script:envFilePath = Join-Path -Path $TestDrive -ChildPath 'valid.env'

            $fileContent = @(
                '# A comment line'
                ''
                'ENTERPRISE_REPO_SMB_SHARE=\\FS01\PowerShellRepo'
                "ENTERPRISE_REPO_CREDENTIAL = 'PSRepoPublisher'"
            )

            Set-Content -Path $script:envFilePath -Value $fileContent
        }

        It 'Should publish the values as environment variables' {
            $null = Import-EnterpriseRepositoryEnvFile -Path $script:envFilePath

            $env:ENTERPRISE_REPO_SMB_SHARE | Should -BeExactly '\\FS01\PowerShellRepo'
        }

        It 'Should strip surrounding quotes and whitespace' {
            $null = Import-EnterpriseRepositoryEnvFile -Path $script:envFilePath

            $env:ENTERPRISE_REPO_CREDENTIAL | Should -BeExactly 'PSRepoPublisher'
        }

        It 'Should return the names of the applied keys' {
            $result = Import-EnterpriseRepositoryEnvFile -Path $script:envFilePath

            $result | Should -HaveCount 2
            $result | Should -Contain 'ENTERPRISE_REPO_SMB_SHARE'
        }
    }

    Context 'When the environment already defines the key' {
        It 'Should not override the existing process environment value' {
            $env:ENTERPRISE_REPO_SMB_SHARE = '\\FS99\CiRepo'

            $envFilePath = Join-Path -Path $TestDrive -ChildPath 'override.env'
            Set-Content -Path $envFilePath -Value 'ENTERPRISE_REPO_SMB_SHARE=\\FS01\PowerShellRepo'

            Import-EnterpriseRepositoryEnvFile -Path $envFilePath | Should -BeNullOrEmpty
            $env:ENTERPRISE_REPO_SMB_SHARE | Should -BeExactly '\\FS99\CiRepo'
        }
    }

    Context 'When the configuration file carries a secret' {
        It 'Should refuse to load the password' {
            $envFilePath = Join-Path -Path $TestDrive -ChildPath 'secret.env'
            Set-Content -Path $envFilePath -Value 'ENTERPRISE_REPO_PASSWORD=NotASecretInGit'

            $null = Import-EnterpriseRepositoryEnvFile -Path $envFilePath -WarningAction SilentlyContinue

            $env:ENTERPRISE_REPO_PASSWORD | Should -BeNullOrEmpty
        }
    }

    Context 'When a line is malformed' {
        It 'Should ignore it and keep processing the file' {
            $envFilePath = Join-Path -Path $TestDrive -ChildPath 'malformed.env'
            Set-Content -Path $envFilePath -Value @('this is not a pair', 'ENTERPRISE_REPO_VAULT=CorpVault')

            $result = Import-EnterpriseRepositoryEnvFile -Path $envFilePath -WarningAction SilentlyContinue

            $result | Should -HaveCount 1
            $env:ENTERPRISE_REPO_VAULT | Should -BeExactly 'CorpVault'
        }
    }
}

Describe 'Get-EnterpriseRepositoryConfiguration' {
    AfterEach {
        foreach ($name in $script:managedEnvironmentVariable)
        {
            Remove-Item -Path "env:$name" -ErrorAction SilentlyContinue
        }
    }

    Context 'When no SMB share is configured' {
        It 'Should report the task as disabled' {
            (Get-EnterpriseRepositoryConfiguration).IsEnabled | Should -BeFalse
        }
    }

    Context 'When the SMB share is configured through the environment' {
        It 'Should report the task as enabled' {
            $env:ENTERPRISE_REPO_SMB_SHARE = '\\FS01\PowerShellRepo'

            $configuration = Get-EnterpriseRepositoryConfiguration

            $configuration.IsEnabled | Should -BeTrue
            $configuration.SmbShare | Should -BeExactly '\\FS01\PowerShellRepo'
        }

        It 'Should trim a trailing separator' {
            $env:ENTERPRISE_REPO_SMB_SHARE = '\\FS01\PowerShellRepo\'

            (Get-EnterpriseRepositoryConfiguration).SmbShare | Should -BeExactly '\\FS01\PowerShellRepo'
        }
    }

    Context 'When an explicit share is passed as a parameter' {
        It 'Should take precedence over the environment variable' {
            $env:ENTERPRISE_REPO_SMB_SHARE = '\\FS01\PowerShellRepo'

            $configuration = Get-EnterpriseRepositoryConfiguration -SmbShare '\\FS02\OverrideRepo'

            $configuration.SmbShare | Should -BeExactly '\\FS02\OverrideRepo'
        }
    }

    Context 'When the dry-run switch is set' {
        It 'Should report WhatIf as <Expected> for the value "<Value>"' -ForEach @(
            @{ Value = 'true'; Expected = $true }
            @{ Value = '1'; Expected = $true }
            @{ Value = 'false'; Expected = $false }
            @{ Value = ''; Expected = $false }
        ) {
            $env:ENTERPRISE_REPO_SMB_SHARE = '\\FS01\PowerShellRepo'
            $env:ENTERPRISE_REPO_WHATIF = $Value

            (Get-EnterpriseRepositoryConfiguration).WhatIf | Should -Be $Expected
        }
    }

    Context 'When every setting is supplied as a parameter' {
        BeforeEach {
            # The environment is fully populated so that precedence is actually exercised.
            $env:ENTERPRISE_REPO_SMB_SHARE = '\\FS99\EnvRepo'
            $env:ENTERPRISE_REPO_CREDENTIAL = 'EnvSecret'
            $env:ENTERPRISE_REPO_VAULT = 'EnvVault'
            $env:ENTERPRISE_REPO_USERNAME = 'CORP\svc_env'
            $env:ENTERPRISE_REPO_MODULE_PATH = './output/module/PSADEngine/9.9.9'
            $env:ENTERPRISE_REPO_WHATIF = 'true'

            $script:configurationParam = @{
                SmbShare             = '\\FS01\PowerShellRepo'
                CredentialSecretName = 'ParamSecret'
                VaultName            = 'ParamVault'
                UserName             = 'CORP\svc_psrepo'
                ModulePath           = './output/module/PSADEngine/1.2.3'
                DryRun               = $false
            }
        }

        It 'Should prefer the parameter over the environment for <Key>' -ForEach @(
            @{ Key = 'SmbShare'; Expected = '\\FS01\PowerShellRepo' }
            @{ Key = 'CredentialSecretName'; Expected = 'ParamSecret' }
            @{ Key = 'VaultName'; Expected = 'ParamVault' }
            @{ Key = 'UserName'; Expected = 'CORP\svc_psrepo' }
            @{ Key = 'ModulePath'; Expected = './output/module/PSADEngine/1.2.3' }
        ) {
            $configuration = Get-EnterpriseRepositoryConfiguration @script:configurationParam

            $configuration[$Key] | Should -BeExactly $Expected
        }

        It 'Should let an explicit -DryRun:$false override ENTERPRISE_REPO_WHATIF' {
            $configuration = Get-EnterpriseRepositoryConfiguration @script:configurationParam

            $configuration.WhatIf | Should -BeFalse
        }
    }

    Context 'When only some settings are supplied as parameters' {
        It 'Should fall back to the environment for the settings left unset' {
            $env:ENTERPRISE_REPO_SMB_SHARE = '\\FS01\PowerShellRepo'
            $env:ENTERPRISE_REPO_VAULT = 'CorpVault'

            $configuration = Get-EnterpriseRepositoryConfiguration -UserName 'CORP\svc_psrepo'

            # Parameter layer.
            $configuration.UserName | Should -BeExactly 'CORP\svc_psrepo'

            # Environment layer, untouched by the parameter layer.
            $configuration.SmbShare | Should -BeExactly '\\FS01\PowerShellRepo'
            $configuration.VaultName | Should -BeExactly 'CorpVault'
        }

        It 'Should ignore an empty parameter so it never shadows the environment' {
            $env:ENTERPRISE_REPO_SMB_SHARE = '\\FS01\PowerShellRepo'

            $configuration = Get-EnterpriseRepositoryConfiguration -SmbShare '   '

            $configuration.SmbShare | Should -BeExactly '\\FS01\PowerShellRepo'
        }
    }

    Context 'When a credential is supplied as a parameter' {
        It 'Should carry it in the returned configuration' {
            $env:ENTERPRISE_REPO_SMB_SHARE = '\\FS01\PowerShellRepo'

            $configuration = Get-EnterpriseRepositoryConfiguration -Credential $script:parameterCredential

            $configuration.Credential | Should -BeOfType [System.Management.Automation.PSCredential]
            $configuration.Credential.UserName | Should -BeExactly 'CORP\adm_jsmith'
        }

        It 'Should never leak the password into the process environment' {
            $env:ENTERPRISE_REPO_SMB_SHARE = '\\FS01\PowerShellRepo'

            $null = Get-EnterpriseRepositoryConfiguration -Credential $script:parameterCredential

            $env:ENTERPRISE_REPO_PASSWORD | Should -BeNullOrEmpty
        }
    }

    Context 'When no credential parameter is supplied' {
        It 'Should report a null credential so the other sources stay in charge' {
            $env:ENTERPRISE_REPO_SMB_SHARE = '\\FS01\PowerShellRepo'

            (Get-EnterpriseRepositoryConfiguration).Credential | Should -BeNullOrEmpty
        }
    }

    Context 'When the Enterprise* parameter aliases are used' {
        It 'Should accept -EnterpriseSmbShare as an alias of -SmbShare' {
            $configuration = Get-EnterpriseRepositoryConfiguration -EnterpriseSmbShare '\\FS01\PowerShellRepo'

            $configuration.SmbShare | Should -BeExactly '\\FS01\PowerShellRepo'
        }

        It 'Should accept -EnterpriseCredential as an alias of -Credential' {
            $configurationParam = @{
                EnterpriseSmbShare   = '\\FS01\PowerShellRepo'
                EnterpriseCredential = $script:parameterCredential
            }

            $configuration = Get-EnterpriseRepositoryConfiguration @configurationParam

            $configuration.Credential.UserName | Should -BeExactly 'CORP\adm_jsmith'
        }
    }
}

Describe 'Resolve-EnterpriseRepositoryCredential' {
    AfterEach {
        foreach ($name in $script:managedEnvironmentVariable)
        {
            Remove-Item -Path "env:$name" -ErrorAction SilentlyContinue
        }
    }

    Context 'When no credential source is declared' {
        It 'Should return null so the build agent context is used' {
            $configuration = @{
                CredentialSecretName = $null
                UserName             = $null
                VaultName            = $null
            }

            Resolve-EnterpriseRepositoryCredential -Configuration $configuration | Should -BeNullOrEmpty
        }

        It 'Should keep working with a legacy configuration that has no Credential key' {
            # Backward compatibility: pre-parameter callers built a hashtable without it.
            $configuration = @{
                CredentialSecretName = $null
                UserName             = $null
                VaultName            = $null
            }

            $configuration.ContainsKey('Credential') | Should -BeFalse

            { Resolve-EnterpriseRepositoryCredential -Configuration $configuration } | Should -Not -Throw
        }
    }

    Context 'When a credential is supplied as a build parameter' {
        It 'Should return it unchanged' {
            $configuration = @{
                Credential           = $script:parameterCredential
                CredentialSecretName = $null
                UserName             = $null
                VaultName            = $null
            }

            $credential = Resolve-EnterpriseRepositoryCredential -Configuration $configuration

            $credential.UserName | Should -BeExactly 'CORP\adm_jsmith'
        }

        It 'Should outrank the user name and password environment variables' {
            $env:ENTERPRISE_REPO_USERNAME = 'CORP\svc_env'
            $env:ENTERPRISE_REPO_PASSWORD = 'P@ssphrase-For-Unit-Test'

            $configuration = @{
                Credential           = $script:parameterCredential
                CredentialSecretName = $null
                UserName             = 'CORP\svc_env'
                VaultName            = $null
            }

            $credential = Resolve-EnterpriseRepositoryCredential -Configuration $configuration

            $credential.UserName | Should -BeExactly 'CORP\adm_jsmith'
            $credential.GetNetworkCredential().Password | Should -BeExactly 'Parameter-Only-Unit-Test'
        }

        It 'Should outrank a SecretManagement secret without reading the vault' {
            Mock -CommandName Get-Secret -MockWith { throw 'The vault must not be queried.' }

            $configuration = @{
                Credential           = $script:parameterCredential
                CredentialSecretName = 'PSRepoPublisher'
                UserName             = $null
                VaultName            = 'CorpVault'
            }

            $credential = Resolve-EnterpriseRepositoryCredential -Configuration $configuration

            $credential.UserName | Should -BeExactly 'CORP\adm_jsmith'

            Should -Invoke -CommandName Get-Secret -Times 0 -Exactly
        }

        It 'Should throw an explicit message when the value is not a PSCredential' {
            $configuration = @{
                Credential           = 'CORP\adm_jsmith'
                CredentialSecretName = $null
                UserName             = $null
                VaultName            = $null
            }

            { Resolve-EnterpriseRepositoryCredential -Configuration $configuration } |
                Should -Throw -ExpectedMessage '*must be a System.Management.Automation.PSCredential*'
        }
    }

    Context 'When a user name and password are provided' {
        It 'Should return a PSCredential carrying those values' {
            $env:ENTERPRISE_REPO_PASSWORD = 'P@ssphrase-For-Unit-Test'

            $configuration = @{
                CredentialSecretName = $null
                UserName             = 'CORP\svc_psrepo'
                VaultName            = $null
            }

            $credential = Resolve-EnterpriseRepositoryCredential -Configuration $configuration

            $credential | Should -BeOfType [System.Management.Automation.PSCredential]
            $credential.UserName | Should -BeExactly 'CORP\svc_psrepo'
            $credential.GetNetworkCredential().Password | Should -BeExactly 'P@ssphrase-For-Unit-Test'
        }
    }

    Context 'When a secret name is declared but SecretManagement is unavailable' {
        BeforeEach {
            Mock -CommandName Get-Command -MockWith { return $null } -ParameterFilter {
                $Name -eq 'Get-Secret'
            }
        }

        It 'Should throw when no fallback credential exists' {
            $configuration = @{
                CredentialSecretName = 'PSRepoPublisher'
                UserName             = $null
                VaultName            = $null
            }

            { Resolve-EnterpriseRepositoryCredential -Configuration $configuration } |
                Should -Throw -ExpectedMessage '*SecretManagement is not available*'
        }

        It 'Should fall back to the user name and password variables' {
            $env:ENTERPRISE_REPO_PASSWORD = 'P@ssphrase-For-Unit-Test'

            $configuration = @{
                CredentialSecretName = 'PSRepoPublisher'
                UserName             = 'CORP\svc_psrepo'
                VaultName            = $null
            }

            $credential = Resolve-EnterpriseRepositoryCredential -Configuration $configuration -WarningAction SilentlyContinue

            $credential.UserName | Should -BeExactly 'CORP\svc_psrepo'
        }
    }
}

Describe 'Get-EnterpriseRepositorySecretCredential' {
    Context 'When the vault returns a PSCredential' {
        BeforeAll {
            $script:vaultCredential = [System.Management.Automation.PSCredential]::new(
                'CORP\svc_psrepo',
                (ConvertTo-SecureString -String 'P@ssphrase-For-Unit-Test' -AsPlainText -Force)
            )
        }

        BeforeEach {
            Mock -CommandName Get-Secret -MockWith { return $script:vaultCredential }
        }

        It 'Should return it unchanged' {
            $configuration = @{
                CredentialSecretName = 'PSRepoPublisher'
                UserName             = $null
                VaultName            = 'CorpVault'
            }

            $credential = Get-EnterpriseRepositorySecretCredential -Configuration $configuration

            $credential.UserName | Should -BeExactly 'CORP\svc_psrepo'
        }

        It 'Should query the configured vault' {
            $configuration = @{
                CredentialSecretName = 'PSRepoPublisher'
                UserName             = $null
                VaultName            = 'CorpVault'
            }

            $null = Get-EnterpriseRepositorySecretCredential -Configuration $configuration

            Should -Invoke -CommandName Get-Secret -Times 1 -Exactly -ParameterFilter {
                $Name -eq 'PSRepoPublisher' -and $Vault -eq 'CorpVault'
            }
        }
    }

    Context 'When the vault returns a SecureString' {
        BeforeEach {
            Mock -CommandName Get-Secret -MockWith {
                return (ConvertTo-SecureString -String 'P@ssphrase-For-Unit-Test' -AsPlainText -Force)
            }
        }

        It 'Should combine it with the configured user name' {
            $configuration = @{
                CredentialSecretName = 'PSRepoPublisher'
                UserName             = 'CORP\svc_psrepo'
                VaultName            = $null
            }

            $credential = Get-EnterpriseRepositorySecretCredential -Configuration $configuration

            $credential.GetNetworkCredential().Password | Should -BeExactly 'P@ssphrase-For-Unit-Test'
        }

        It 'Should throw when the user name is missing' {
            $configuration = @{
                CredentialSecretName = 'PSRepoPublisher'
                UserName             = $null
                VaultName            = $null
            }

            { Get-EnterpriseRepositorySecretCredential -Configuration $configuration } |
                Should -Throw -ExpectedMessage '*ENTERPRISE_REPO_USERNAME*'
        }
    }

    Context 'When the vault returns an unsupported type' {
        BeforeEach {
            Mock -CommandName Get-Secret -MockWith { return 'a plain string' }
        }

        It 'Should throw an explicit message' {
            $configuration = @{
                CredentialSecretName = 'PSRepoPublisher'
                UserName             = 'CORP\svc_psrepo'
                VaultName            = $null
            }

            { Get-EnterpriseRepositorySecretCredential -Configuration $configuration } |
                Should -Throw -ExpectedMessage '*unsupported type*'
        }
    }

    Context 'When the vault read fails' {
        BeforeEach {
            Mock -CommandName Get-Secret -MockWith { throw 'Vault is locked' }
        }

        It 'Should surface a clear message' {
            $configuration = @{
                CredentialSecretName = 'PSRepoPublisher'
                UserName             = 'CORP\svc_psrepo'
                VaultName            = $null
            }

            { Get-EnterpriseRepositorySecretCredential -Configuration $configuration } |
                Should -Throw -ExpectedMessage '*Unable to read the secret*'
        }
    }
}

Describe 'Test-EnterpriseRepositoryTruthyValue' {
    Context 'When the value comes from a build parameter' {
        It 'Should return <Expected> for a [bool] <Value>' -ForEach @(
            @{ Value = $true; Expected = $true }
            @{ Value = $false; Expected = $false }
        ) {
            Test-EnterpriseRepositoryTruthyValue -Value $Value | Should -Be $Expected
        }

        It 'Should honour a present SwitchParameter' {
            Test-EnterpriseRepositoryTruthyValue -Value ([System.Management.Automation.SwitchParameter]::new($true)) |
                Should -BeTrue
        }

        It 'Should honour an absent SwitchParameter' {
            Test-EnterpriseRepositoryTruthyValue -Value ([System.Management.Automation.SwitchParameter]::new($false)) |
                Should -BeFalse
        }
    }

    Context 'When the value comes from an environment variable' {
        It 'Should return <Expected> for the string "<Value>"' -ForEach @(
            @{ Value = 'true'; Expected = $true }
            @{ Value = 'True'; Expected = $true }
            @{ Value = 'TRUE'; Expected = $true }
            @{ Value = '1'; Expected = $true }
            @{ Value = 'yes'; Expected = $true }
            @{ Value = ' on '; Expected = $true }
            @{ Value = 'false'; Expected = $false }
            @{ Value = '0'; Expected = $false }
            @{ Value = 'maybe'; Expected = $false }
            @{ Value = ''; Expected = $false }
        ) {
            Test-EnterpriseRepositoryTruthyValue -Value $Value | Should -Be $Expected
        }
    }

    Context 'When the value is null' {
        It 'Should return false' {
            Test-EnterpriseRepositoryTruthyValue -Value $null | Should -BeFalse
        }
    }
}

Describe 'ConvertFrom-EnterpriseRepositoryParameterTable' {
    Context 'When the table is null or empty' {
        It 'Should return an empty hashtable for <Name>' -ForEach @(
            @{ Name = 'null'; Table = $null }
            @{ Name = 'an empty hashtable'; Table = @{} }
        ) {
            $result = ConvertFrom-EnterpriseRepositoryParameterTable -InputObject $Table

            $result | Should -BeOfType [System.Collections.Hashtable]
            $result.Count | Should -Be 0
        }
    }

    Context 'When the table uses the documented Enterprise* names' {
        It 'Should map "<Key>" to the canonical "<Canonical>"' -ForEach @(
            @{ Key = 'EnterpriseSmbShare'; Canonical = 'SmbShare'; Value = '\\FS01\PowerShellRepo' }
            @{ Key = 'EnterpriseUserName'; Canonical = 'UserName'; Value = 'CORP\svc_psrepo' }
            @{ Key = 'EnterpriseCredentialSecretName'; Canonical = 'CredentialSecretName'; Value = 'PSRepoPublisher' }
            @{ Key = 'EnterpriseVaultName'; Canonical = 'VaultName'; Value = 'CorpVault' }
            @{ Key = 'EnterpriseModulePath'; Canonical = 'ModulePath'; Value = './output/module/PSADEngine/1.2.3' }
            @{ Key = 'EnterpriseDryRun'; Canonical = 'DryRun'; Value = $true }
        ) {
            $result = ConvertFrom-EnterpriseRepositoryParameterTable -InputObject @{ $Key = $Value }

            $result[$Canonical] | Should -Be $Value
        }

        It 'Should accept the legacy EnterpriseRepositorySmbShare spelling' {
            $result = ConvertFrom-EnterpriseRepositoryParameterTable -InputObject @{
                EnterpriseRepositorySmbShare = '\\FS01\PowerShellRepo'
            }

            $result['SmbShare'] | Should -BeExactly '\\FS01\PowerShellRepo'
        }

        It 'Should match keys case-insensitively, like PowerShell parameter binding' {
            $result = ConvertFrom-EnterpriseRepositoryParameterTable -InputObject @{
                enterprisesmbshare = '\\FS01\PowerShellRepo'
            }

            $result['SmbShare'] | Should -BeExactly '\\FS01\PowerShellRepo'
        }

        It 'Should accept an ordered dictionary' {
            $orderedTable = [ordered] @{
                EnterpriseSmbShare = '\\FS01\PowerShellRepo'
                EnterpriseDryRun   = $true
            }

            $result = ConvertFrom-EnterpriseRepositoryParameterTable -InputObject $orderedTable

            $result['SmbShare'] | Should -BeExactly '\\FS01\PowerShellRepo'
            $result['DryRun'] | Should -BeTrue
        }
    }

    Context 'When a value is not actually supplied' {
        It 'Should drop <Name> so it cannot shadow an environment variable' -ForEach @(
            @{ Name = 'a null value'; Value = $null }
            @{ Name = 'an empty string'; Value = '' }
            @{ Name = 'a whitespace-only string'; Value = '   ' }
        ) {
            $result = ConvertFrom-EnterpriseRepositoryParameterTable -InputObject @{
                EnterpriseSmbShare = $Value
            }

            $result.ContainsKey('SmbShare') | Should -BeFalse
        }

        It 'Should keep a $false dry-run flag, which is a real instruction' {
            $result = ConvertFrom-EnterpriseRepositoryParameterTable -InputObject @{
                EnterpriseDryRun = $false
            }

            $result.ContainsKey('DryRun') | Should -BeTrue
            $result['DryRun'] | Should -BeFalse
        }
    }

    Context 'When the table carries unrelated keys' {
        It 'Should ignore them so one table can drive several tasks' {
            $result = ConvertFrom-EnterpriseRepositoryParameterTable -InputObject @{
                EnterpriseSmbShare = '\\FS01\PowerShellRepo'
                SomeOtherTaskInput = 'irrelevant'
            }

            $result.Count | Should -Be 1
            $result.ContainsKey('SmbShare') | Should -BeTrue
        }
    }

    Context 'When the credential is not a PSCredential' {
        It 'Should throw an explicit, actionable message' {
            { ConvertFrom-EnterpriseRepositoryParameterTable -InputObject @{ EnterpriseCredential = 'CORP\svc_psrepo' } } |
                Should -Throw -ExpectedMessage '*must be a System.Management.Automation.PSCredential*'
        }

        It 'Should accept a real PSCredential' {
            $result = ConvertFrom-EnterpriseRepositoryParameterTable -InputObject @{
                EnterpriseCredential = $script:parameterCredential
            }

            $result['Credential'].UserName | Should -BeExactly 'CORP\adm_jsmith'
        }
    }

    Context 'When the input is not a dictionary' {
        It 'Should throw and show the expected syntax' {
            { ConvertFrom-EnterpriseRepositoryParameterTable -InputObject 'EnterpriseSmbShare=\\FS01\PowerShellRepo' } |
                Should -Throw -ExpectedMessage '*must be a hashtable*'
        }
    }
}

Describe 'Resolve-EnterpriseRepositorySetting' {
    AfterEach {
        Remove-Item -Path 'env:ENTERPRISE_REPO_SMB_SHARE' -ErrorAction SilentlyContinue
    }

    Context 'When both a parameter and an environment variable are set' {
        It 'Should return the parameter' {
            $env:ENTERPRISE_REPO_SMB_SHARE = '\\FS99\EnvRepo'

            $settingParam = @{
                ParameterValue          = '\\FS01\PowerShellRepo'
                EnvironmentVariableName = 'ENTERPRISE_REPO_SMB_SHARE'
            }

            Resolve-EnterpriseRepositorySetting @settingParam | Should -BeExactly '\\FS01\PowerShellRepo'
        }
    }

    Context 'When only the environment variable is set' {
        It 'Should return the environment value for <Name>' -ForEach @(
            @{ Name = 'an unbound parameter'; ParameterValue = $null }
            @{ Name = 'an empty parameter'; ParameterValue = '' }
            @{ Name = 'a whitespace-only parameter'; ParameterValue = "`t " }
        ) {
            $env:ENTERPRISE_REPO_SMB_SHARE = '\\FS99\EnvRepo'

            $settingParam = @{
                ParameterValue          = $ParameterValue
                EnvironmentVariableName = 'ENTERPRISE_REPO_SMB_SHARE'
            }

            Resolve-EnterpriseRepositorySetting @settingParam | Should -BeExactly '\\FS99\EnvRepo'
        }
    }

    Context 'When neither source is set' {
        It 'Should return null' {
            $settingParam = @{
                ParameterValue          = ''
                EnvironmentVariableName = 'ENTERPRISE_REPO_SMB_SHARE'
            }

            Resolve-EnterpriseRepositorySetting @settingParam | Should -BeNullOrEmpty
        }
    }
}

Describe 'Get-EnterpriseRepositoryCredentialSource' {
    AfterEach {
        foreach ($name in $script:managedEnvironmentVariable)
        {
            Remove-Item -Path "env:$name" -ErrorAction SilentlyContinue
        }
    }

    It 'Should report the build parameter when a PSCredential was supplied' {
        $configuration = @{
            Credential           = $script:parameterCredential
            CredentialSecretName = 'PSRepoPublisher'
            UserName             = 'CORP\svc_psrepo'
        }

        Get-EnterpriseRepositoryCredentialSource -Configuration $configuration |
            Should -BeExactly 'build parameter (PSCredential)'
    }

    It 'Should report the vault when only a secret name is configured' {
        $configuration = @{
            Credential           = $null
            CredentialSecretName = 'PSRepoPublisher'
            UserName             = $null
        }

        Get-EnterpriseRepositoryCredentialSource -Configuration $configuration |
            Should -BeLike '*PSRepoPublisher*'
    }

    It 'Should report the environment variables when only they are configured' {
        $env:ENTERPRISE_REPO_PASSWORD = 'P@ssphrase-For-Unit-Test'

        $configuration = @{
            Credential           = $null
            CredentialSecretName = $null
            UserName             = 'CORP\svc_psrepo'
        }

        Get-EnterpriseRepositoryCredentialSource -Configuration $configuration |
            Should -BeExactly 'ENTERPRISE_REPO_USERNAME / ENTERPRISE_REPO_PASSWORD'
    }

    It 'Should report the build agent context when nothing is configured' {
        $configuration = @{
            Credential           = $null
            CredentialSecretName = $null
            UserName             = $null
        }

        Get-EnterpriseRepositoryCredentialSource -Configuration $configuration |
            Should -BeExactly 'build agent security context'
    }

    It 'Should never disclose the password' {
        $env:ENTERPRISE_REPO_PASSWORD = 'P@ssphrase-For-Unit-Test'

        $configuration = @{
            Credential           = $script:parameterCredential
            CredentialSecretName = $null
            UserName             = 'CORP\svc_psrepo'
        }

        Get-EnterpriseRepositoryCredentialSource -Configuration $configuration |
            Should -Not -BeLike '*P@ssphrase*'
    }
}

Describe 'Enterprise repository settings precedence' -Tag 'Precedence' {
    <#
        End-to-end verification of the documented contract:
        -Parameters > individual task parameter > environment variable > default.
        The two parameter layers are merged exactly as the build task merges them.
    #>
    AfterEach {
        foreach ($name in $script:managedEnvironmentVariable)
        {
            Remove-Item -Path "env:$name" -ErrorAction SilentlyContinue
        }
    }

    BeforeAll {
        function Invoke-MergedConfiguration
        {
            <#
                Mirrors the merge performed by Publish_Module_To_EnterpriseRepository:
                the individual task parameters form the lower explicit layer, and the
                -Parameters table is overlaid on top of it.
            #>
            [CmdletBinding()]
            [OutputType([System.Collections.Hashtable])]
            param
            (
                [Parameter()]
                [AllowNull()]
                [System.Object]
                $TaskParameter,

                [Parameter()]
                [AllowNull()]
                [System.Object]
                $ParameterTable
            )

            $settingOverride = ConvertFrom-EnterpriseRepositoryParameterTable -InputObject $TaskParameter

            foreach ($entry in (ConvertFrom-EnterpriseRepositoryParameterTable -InputObject $ParameterTable).GetEnumerator())
            {
                $settingOverride[$entry.Key] = $entry.Value
            }

            $configurationParam = @{}

            foreach ($entry in $settingOverride.GetEnumerator())
            {
                $configurationParam[$entry.Key] = $entry.Value
            }

            return (Get-EnterpriseRepositoryConfiguration @configurationParam)
        }
    }

    Context 'When only the environment is configured (backward compatible path)' {
        It 'Should behave exactly as before the parameters were introduced' {
            $env:ENTERPRISE_REPO_SMB_SHARE = '\\FS99\EnvRepo'
            $env:ENTERPRISE_REPO_USERNAME = 'CORP\svc_env'

            $configuration = Invoke-MergedConfiguration

            $configuration.IsEnabled | Should -BeTrue
            $configuration.SmbShare | Should -BeExactly '\\FS99\EnvRepo'
            $configuration.UserName | Should -BeExactly 'CORP\svc_env'
            $configuration.Credential | Should -BeNullOrEmpty
        }
    }

    Context 'When an individual task parameter is set' {
        It 'Should win over the environment variable' {
            $env:ENTERPRISE_REPO_SMB_SHARE = '\\FS99\EnvRepo'

            $configuration = Invoke-MergedConfiguration -TaskParameter @{
                SmbShare = '\\FS01\TaskRepo'
            }

            $configuration.SmbShare | Should -BeExactly '\\FS01\TaskRepo'
        }
    }

    Context 'When both an individual task parameter and -Parameters are set' {
        It 'Should let -Parameters win, being the most explicit layer' {
            $env:ENTERPRISE_REPO_SMB_SHARE = '\\FS99\EnvRepo'

            $mergeParam = @{
                TaskParameter  = @{ SmbShare = '\\FS01\TaskRepo' }
                ParameterTable = @{ EnterpriseSmbShare = '\\FS02\ParameterRepo' }
            }

            $configuration = Invoke-MergedConfiguration @mergeParam

            $configuration.SmbShare | Should -BeExactly '\\FS02\ParameterRepo'
        }

        It 'Should keep the task parameter for settings absent from -Parameters' {
            $mergeParam = @{
                TaskParameter  = @{
                    SmbShare  = '\\FS01\TaskRepo'
                    VaultName = 'TaskVault'
                }
                ParameterTable = @{ EnterpriseSmbShare = '\\FS02\ParameterRepo' }
            }

            $configuration = Invoke-MergedConfiguration @mergeParam

            $configuration.SmbShare | Should -BeExactly '\\FS02\ParameterRepo'
            $configuration.VaultName | Should -BeExactly 'TaskVault'
        }
    }

    Context 'When nothing at all is configured' {
        It 'Should report the task as disabled so the build is not failed' {
            $configuration = Invoke-MergedConfiguration

            $configuration.IsEnabled | Should -BeFalse
            $configuration.SmbShare | Should -BeNullOrEmpty
            $configuration.WhatIf | Should -BeFalse
        }
    }

    Context 'When the credential is passed through -Parameters as documented' {
        It 'Should reach Resolve-EnterpriseRepositoryCredential unchanged' {
            $env:ENTERPRISE_REPO_SMB_SHARE = '\\FS99\EnvRepo'

            $configuration = Invoke-MergedConfiguration -ParameterTable @{
                EnterpriseSmbShare   = '\\FS01\PowerShellRepo'
                EnterpriseCredential = $script:parameterCredential
            }

            $credential = Resolve-EnterpriseRepositoryCredential -Configuration $configuration

            $configuration.SmbShare | Should -BeExactly '\\FS01\PowerShellRepo'
            $credential.UserName | Should -BeExactly 'CORP\adm_jsmith'
        }
    }
}

Describe 'Build entry point parameter contract' -Tag 'Precedence' {
    <#
        Invoke-Build has no -Parameters parameter of its own: it exposes the build
        script's parameters as dynamic parameters. './build.ps1 -Parameters @{ ... }'
        therefore only binds because build.ps1 declares it, and the task file only sees
        the value because it reads it through 'property Parameters'. Both halves of that
        contract are asserted statically, since executing a full build is out of scope
        for a unit test.
    #>
    BeforeAll {
        $script:buildScriptPath = Join-Path -Path $script:projectPath -ChildPath 'build.ps1'

        $script:taskScriptPath = Join-Path -Path $script:projectPath -ChildPath '.build' |
            Join-Path -ChildPath 'PublishEnterpriseRepository.build.ps1'

        $script:buildScriptParameter = (Get-Command -Name $script:buildScriptPath).Parameters

        $script:taskScriptContent = Get-Content -Path $script:taskScriptPath -Raw
    }

    It 'Should declare a -Parameters parameter on build.ps1' {
        $script:buildScriptParameter.ContainsKey('Parameters') | Should -BeTrue
    }

    It 'Should type the -Parameters parameter as a hashtable' {
        $script:buildScriptParameter['Parameters'].ParameterType |
            Should -Be ([System.Collections.Hashtable])
    }

    It 'Should not collide with an Invoke-Build reserved parameter name' {
        # Invoke-Build refuses a build script using any of these names.
        $reservedName = @('Task', 'File', 'Result', 'Safe', 'Summary', 'WhatIf')

        $reservedName | Should -Not -Contain 'Parameters'
    }

    It 'Should read the parameter table in the task through the Invoke-Build property' {
        $script:taskScriptContent | Should -Match '\$Parameters\s*=\s*\(property Parameters'
    }

    It 'Should declare the task parameter <Name>' -ForEach @(
        @{ Name = 'EnterpriseSmbShare' }
        @{ Name = 'EnterpriseCredential' }
        @{ Name = 'EnterpriseUserName' }
        @{ Name = 'EnterpriseCredentialSecretName' }
        @{ Name = 'EnterpriseVaultName' }
        @{ Name = 'EnterpriseModulePath' }
        @{ Name = 'EnterpriseDryRun' }
    ) {
        $script:taskScriptContent | Should -Match "\`$$Name\s*=\s*\(property $Name"
    }

    It 'Should keep the legacy EnterpriseRepositorySmbShare parameter for compatibility' {
        $script:taskScriptContent | Should -Match '\$EnterpriseRepositorySmbShare\s*=\s*\(property EnterpriseRepositorySmbShare'
    }
}
