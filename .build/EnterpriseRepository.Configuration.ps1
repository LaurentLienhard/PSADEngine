<#
    .SYNOPSIS
        Configuration and credential helpers for the Invoke-Build task
        'Publish_Module_To_EnterpriseRepository'.

    .DESCRIPTION
        Resolves where the enterprise SMB PowerShell repository is, and which identity
        must be used to write to it. The file is deliberately free of any Invoke-Build
        'task' statement so that Pester can dot-source it directly.

        It is auto-loaded by build.ps1, which dot-sources every '*.ps1' found under the
        './.build/' folder before the workflows declared in build.yaml are created.

    .NOTES
        Tier 0 note: the internal repository is a software supply chain component. Never
        store its credentials in the repository. Use Microsoft.PowerShell.SecretManagement
        on a workstation and GitHub Secrets (or Azure DevOps secret variables) in CI/CD.
#>

$script:EnterpriseRepositoryEnvironmentVariable = @{
    SmbShare       = 'ENTERPRISE_REPO_SMB_SHARE'
    CredentialName = 'ENTERPRISE_REPO_CREDENTIAL'
    VaultName      = 'ENTERPRISE_REPO_VAULT'
    UserName       = 'ENTERPRISE_REPO_USERNAME'
    Password       = 'ENTERPRISE_REPO_PASSWORD'
    ModulePath     = 'ENTERPRISE_REPO_MODULE_PATH'
    WhatIf         = 'ENTERPRISE_REPO_WHATIF'
}

<#
    Keys that must never be sourced from an on-disk configuration file. A password belongs
    in a secret vault or in a CI/CD secret store, never in a flat file that a developer can
    accidentally commit.
#>
$script:EnterpriseRepositoryForbiddenFileKey = @(
    'ENTERPRISE_REPO_PASSWORD'
)

function Import-EnterpriseRepositoryEnvFile
{
    <#
        .SYNOPSIS
            Loads non-secret KEY=VALUE pairs from a local, git-ignored configuration file.

        .DESCRIPTION
            Parses a simple '.env' style file and publishes each key as a process level
            environment variable. Values already present in the process environment always
            win, so a CI/CD runner (GitHub Actions, Azure Pipelines) can never be silently
            overridden by a developer workstation file. Secret bearing keys are rejected
            with a warning instead of being loaded.

        .PARAMETER Path
            Full path to the configuration file. A missing file is not an error; the
            function simply reports that nothing was applied.

        .EXAMPLE
            Import-EnterpriseRepositoryEnvFile -Path 'C:\src\PSADEngine\.enterprise-repo.env'

            Loads the local enterprise repository settings for an interactive build.

        .OUTPUTS
            System.String[]. The names of the environment variables that were applied.
    #>
    [CmdletBinding()]
    [OutputType([System.String[]])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Path
    )

    $appliedKey = [System.Collections.Generic.List[System.String]]::new()

    if (-not (Test-Path -Path $Path -PathType Leaf))
    {
        Write-Verbose -Message "No local enterprise repository configuration file at '$Path'."

        return $appliedKey.ToArray()
    }

    Write-Verbose -Message "Reading local enterprise repository configuration from '$Path'."

    foreach ($line in (Get-Content -Path $Path -ErrorAction Stop))
    {
        if ([string]::IsNullOrWhiteSpace($line) -or $line.TrimStart().StartsWith('#'))
        {
            continue
        }

        $parsedLine = [regex]::Match($line, '^\s*(?<key>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?<value>.*)$')

        if (-not $parsedLine.Success)
        {
            Write-Warning -Message "Ignoring malformed line in '$Path': $line"

            continue
        }

        $key = $parsedLine.Groups['key'].Value
        $value = $parsedLine.Groups['value'].Value.Trim().Trim('"').Trim("'")

        if ($key -in $script:EnterpriseRepositoryForbiddenFileKey)
        {
            Write-Warning -Message (
                "Refusing to load '$key' from '$Path'. Store the password in a " +
                'SecretManagement vault or in a CI/CD secret instead.'
            )

            continue
        }

        $existingValue = [System.Environment]::GetEnvironmentVariable($key)

        if (-not [string]::IsNullOrWhiteSpace($existingValue))
        {
            Write-Verbose -Message "Environment variable '$key' is already set; file value ignored."

            continue
        }

        Set-Item -Path "env:$key" -Value $value
        $appliedKey.Add($key)
    }

    return $appliedKey.ToArray()
}

function Get-EnterpriseRepositoryConfiguration
{
    <#
        .SYNOPSIS
            Builds the enterprise repository publishing configuration from the environment.

        .DESCRIPTION
            Resolves every setting used by the 'Publish_Module_To_EnterpriseRepository'
            build task from process environment variables, optionally seeded by a local
            git-ignored configuration file. The returned object reports whether the task is
            enabled, which is driven exclusively by the presence of the SMB share variable
            so that a build without enterprise configuration simply skips the task.

        .PARAMETER LocalConfigurationPath
            Optional path to a local '.env' style file used to seed the environment on a
            developer workstation. Values already in the environment take precedence.

        .PARAMETER SmbShare
            Optional explicit UNC path that overrides the ENTERPRISE_REPO_SMB_SHARE
            environment variable, for example when the value is passed as an Invoke-Build
            property.

        .EXAMPLE
            Get-EnterpriseRepositoryConfiguration -LocalConfigurationPath './.enterprise-repo.env'

            Returns the resolved enterprise repository configuration for the current build.

        .OUTPUTS
            System.Collections.Hashtable
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter()]
        [System.String]
        $LocalConfigurationPath,

        [Parameter()]
        [System.String]
        $SmbShare
    )

    if (-not [string]::IsNullOrWhiteSpace($LocalConfigurationPath))
    {
        $null = Import-EnterpriseRepositoryEnvFile -Path $LocalConfigurationPath
    }

    $variableName = $script:EnterpriseRepositoryEnvironmentVariable

    $resolvedShare = if (-not [string]::IsNullOrWhiteSpace($SmbShare))
    {
        $SmbShare
    }
    else
    {
        [System.Environment]::GetEnvironmentVariable($variableName.SmbShare)
    }

    if (-not [string]::IsNullOrWhiteSpace($resolvedShare))
    {
        # Normalise so that Path.Combine() never produces a double separator.
        $resolvedShare = $resolvedShare.Trim().TrimEnd('\', '/')
    }

    $whatIfValue = [System.Environment]::GetEnvironmentVariable($variableName.WhatIf)
    $isWhatIf = $whatIfValue -in @('1', 'true', 'True', 'TRUE', 'yes', 'Yes')

    return @{
        IsEnabled            = -not [string]::IsNullOrWhiteSpace($resolvedShare)
        SmbShare             = $resolvedShare
        CredentialSecretName = [System.Environment]::GetEnvironmentVariable($variableName.CredentialName)
        VaultName            = [System.Environment]::GetEnvironmentVariable($variableName.VaultName)
        UserName             = [System.Environment]::GetEnvironmentVariable($variableName.UserName)
        ModulePath           = [System.Environment]::GetEnvironmentVariable($variableName.ModulePath)
        WhatIf               = $isWhatIf
    }
}

function Resolve-EnterpriseRepositoryCredential
{
    <#
        .SYNOPSIS
            Resolves the PSCredential used to authenticate against the SMB repository.

        .DESCRIPTION
            Supports two credential sources, in order of preference:

            1. A SecretManagement secret, named by ENTERPRISE_REPO_CREDENTIAL, holding
               either a PSCredential or a SecureString (the latter requires
               ENTERPRISE_REPO_USERNAME).
            2. ENTERPRISE_REPO_USERNAME plus ENTERPRISE_REPO_PASSWORD, which is the
               pattern used by CI/CD secret injection (GitHub Secrets, Azure DevOps).

            When no credential source is declared, $null is returned and the caller is
            expected to use the integrated security context of the build agent. When a
            source is declared but cannot be resolved, the function throws, because a
            half-configured credential must never silently fall back to the build agent
            identity.

        .PARAMETER Configuration
            The hashtable returned by Get-EnterpriseRepositoryConfiguration.

        .EXAMPLE
            $credential = Resolve-EnterpriseRepositoryCredential -Configuration $configuration

            Returns a PSCredential, or $null when the build agent identity should be used.

        .OUTPUTS
            System.Management.Automation.PSCredential
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCredential])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingConvertToSecureStringWithPlainText', '',
        Justification = 'CI/CD secret stores expose secrets as plain text environment variables; conversion is unavoidable at that boundary.'
    )]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [System.Collections.Hashtable]
        $Configuration
    )

    $secretName = $Configuration['CredentialSecretName']
    $userName = $Configuration['UserName']
    $password = [System.Environment]::GetEnvironmentVariable(
        $script:EnterpriseRepositoryEnvironmentVariable.Password
    )

    $hasSecretName = -not [string]::IsNullOrWhiteSpace($secretName)
    $hasInlineCredential = -not [string]::IsNullOrWhiteSpace($userName) -and -not [string]::IsNullOrWhiteSpace($password)

    if (-not $hasSecretName -and -not $hasInlineCredential)
    {
        Write-Verbose -Message 'No enterprise repository credential declared; using the build agent security context.'

        return $null
    }

    if ($hasSecretName)
    {
        $secretCredential = Get-EnterpriseRepositorySecretCredential -Configuration $Configuration -AllowFallback:$hasInlineCredential

        if ($null -ne $secretCredential)
        {
            return $secretCredential
        }
    }

    $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force

    return [System.Management.Automation.PSCredential]::new($userName, $securePassword)
}

function Get-EnterpriseRepositorySecretCredential
{
    <#
        .SYNOPSIS
            Reads the repository credential from a SecretManagement vault.

        .DESCRIPTION
            Retrieves the secret named by ENTERPRISE_REPO_CREDENTIAL and converts it into a
            PSCredential. A PSCredential secret is returned as is; a SecureString secret is
            combined with ENTERPRISE_REPO_USERNAME. Returns $null only when the
            SecretManagement module is absent and the caller explicitly allows falling back
            to the user name and password environment variables.

        .PARAMETER Configuration
            The hashtable returned by Get-EnterpriseRepositoryConfiguration.

        .PARAMETER AllowFallback
            Indicates that a user name and password pair is available, so an absent
            SecretManagement module is a warning rather than a terminating error.

        .EXAMPLE
            Get-EnterpriseRepositorySecretCredential -Configuration $configuration

            Returns the PSCredential stored in the configured SecretManagement vault.

        .OUTPUTS
            System.Management.Automation.PSCredential
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCredential])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [System.Collections.Hashtable]
        $Configuration,

        [Parameter()]
        [System.Management.Automation.SwitchParameter]
        $AllowFallback
    )

    $secretName = $Configuration['CredentialSecretName']

    if ($null -eq (Get-Command -Name 'Get-Secret' -ErrorAction SilentlyContinue))
    {
        if (-not $AllowFallback)
        {
            throw (
                "The secret '$secretName' was requested but the module " +
                'Microsoft.PowerShell.SecretManagement is not available, and no ' +
                'ENTERPRISE_REPO_USERNAME/ENTERPRISE_REPO_PASSWORD fallback was provided.'
            )
        }

        Write-Warning -Message 'Microsoft.PowerShell.SecretManagement is not available; falling back to the user name and password variables.'

        return $null
    }

    $secretParam = @{
        Name        = $secretName
        ErrorAction = 'Stop'
    }

    if (-not [string]::IsNullOrWhiteSpace($Configuration['VaultName']))
    {
        $secretParam['Vault'] = $Configuration['VaultName']
    }

    try
    {
        $secret = Get-Secret @secretParam
    }
    catch
    {
        throw "Unable to read the secret '$secretName' from the SecretManagement vault: $($_.Exception.Message)"
    }

    if ($secret -is [System.Management.Automation.PSCredential])
    {
        return $secret
    }

    if ($secret -is [System.Security.SecureString])
    {
        if ([string]::IsNullOrWhiteSpace($Configuration['UserName']))
        {
            throw (
                "The secret '$secretName' is a SecureString, so the user name must also " +
                'be supplied through ENTERPRISE_REPO_USERNAME.'
            )
        }

        return [System.Management.Automation.PSCredential]::new($Configuration['UserName'], $secret)
    }

    throw (
        "The secret '$secretName' is of unsupported type '$($secret.GetType().FullName)'. " +
        'Store a PSCredential or a SecureString.'
    )
}
