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
