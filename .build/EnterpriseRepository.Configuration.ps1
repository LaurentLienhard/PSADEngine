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

        PRECEDENCE
        Every setting is resolved with the same deterministic order:

            1. Build parameters   ./build.ps1 -Parameters @{ EnterpriseSmbShare = '...' }
                                  (or the matching Invoke-Build property / session
                                  variable, e.g. $EnterpriseSmbShare)
            2. Process environment variables (ENTERPRISE_REPO_*), which a CI/CD runner
               injects from GitHub Secrets or Azure DevOps secret variables
            3. The git-ignored './.enterprise-repo.env' file, which only seeds environment
               variables that are not already defined
            4. Built-in defaults (generally $null, which disables the feature)

        Parameters are the preferred path for interactive publishing: a [PSCredential]
        passed as a parameter never reaches the process environment, the command line or
        the shell history, unlike ENTERPRISE_REPO_PASSWORD.

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
    Accepted spellings for every setting that can be supplied through the build parameter
    table. The canonical name (the key) is what Get-EnterpriseRepositoryConfiguration
    expects; the aliases exist so that a caller can use the short 'Enterprise*' form, the
    historical 'EnterpriseRepository*' form, or the bare setting name.
#>
$script:EnterpriseRepositoryParameterAlias = @{
    SmbShare             = @(
        'SmbShare'
        'EnterpriseSmbShare'
        'EnterpriseRepositorySmbShare'
    )
    Credential           = @(
        'Credential'
        'EnterpriseCredential'
        'EnterpriseRepositoryCredential'
    )
    UserName             = @(
        'UserName'
        'EnterpriseUserName'
        'EnterpriseRepositoryUserName'
    )
    CredentialSecretName = @(
        'CredentialSecretName'
        'EnterpriseCredentialSecretName'
        'EnterpriseRepositoryCredentialSecretName'
    )
    VaultName            = @(
        'VaultName'
        'EnterpriseVaultName'
        'EnterpriseRepositoryVaultName'
    )
    ModulePath           = @(
        'ModulePath'
        'EnterpriseModulePath'
        'EnterpriseRepositoryModulePath'
    )
    DryRun               = @(
        'DryRun'
        'EnterpriseDryRun'
        'EnterpriseWhatIf'
        'EnterpriseRepositoryDryRun'
    )
}

<#
    Keys that must never be sourced from an on-disk configuration file. A password belongs
    in a secret vault or in a CI/CD secret store, never in a flat file that a developer can
    accidentally commit.
#>
$script:EnterpriseRepositoryForbiddenFileKey = @(
    'ENTERPRISE_REPO_PASSWORD'
)

<#
    Values accepted as a boolean 'true'. The comparison operators used against this list
    are case-insensitive, so only the lower-case spelling needs to be declared.
#>
$script:EnterpriseRepositoryTruthyValue = @(
    '1'
    'true'
    'yes'
    'y'
    'on'
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

            Build parameters are resolved before this file is even consulted, so a value
            passed through './build.ps1 -Parameters @{ ... }' always wins.

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
                'SecretManagement vault, pass a PSCredential through ' +
                "'./build.ps1 -Parameters @{ EnterpriseCredential = (Get-Credential) }', " +
                'or use a CI/CD secret instead.'
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

function Test-EnterpriseRepositoryTruthyValue
{
    <#
        .SYNOPSIS
            Normalises the many spellings of a boolean flag into a [System.Boolean].

        .DESCRIPTION
            A dry-run flag can reach the build as a real [System.Boolean] or
            [System.Management.Automation.SwitchParameter] when it is passed as a build
            parameter, or as an opaque string when it comes from an environment variable
            or from the '.enterprise-repo.env' file. This helper collapses all of those
            representations into a single boolean so the caller never has to care about
            the source.

        .PARAMETER Value
            The raw value to evaluate. $null and unrecognised values evaluate to $false.

        .EXAMPLE
            Test-EnterpriseRepositoryTruthyValue -Value 'TRUE'

            Returns $true.

        .EXAMPLE
            Test-EnterpriseRepositoryTruthyValue -Value $env:ENTERPRISE_REPO_WHATIF

            Returns $true when the environment variable holds '1', 'true', 'yes', 'y' or
            'on', in any casing.

        .OUTPUTS
            System.Boolean
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Position = 0)]
        [AllowNull()]
        [System.Object]
        $Value
    )

    if ($null -eq $Value)
    {
        return $false
    }

    if ($Value -is [System.Management.Automation.SwitchParameter])
    {
        return $Value.IsPresent
    }

    if ($Value -is [System.Boolean])
    {
        return $Value
    }

    $normalisedValue = ([System.String] $Value).Trim()

    # -in is case-insensitive, so 'True', 'TRUE' and 'true' are all honoured.
    return ($normalisedValue -in $script:EnterpriseRepositoryTruthyValue)
}

function ConvertFrom-EnterpriseRepositoryParameterTable
{
    <#
        .SYNOPSIS
            Normalises a build parameter table into canonical enterprise repository
            settings.

        .DESCRIPTION
            Accepts the hashtable supplied through
            './build.ps1 -Parameters @{ ... }' - or a hashtable assembled from the
            individual Invoke-Build task parameters - and returns a hashtable whose keys
            match the parameter names of Get-EnterpriseRepositoryConfiguration.

            Keys are matched case-insensitively against a set of accepted aliases, so
            'EnterpriseSmbShare', 'EnterpriseRepositorySmbShare' and 'SmbShare' all map to
            the canonical 'SmbShare'. Unrelated keys are ignored, which allows a single
            parameter table to carry settings for several build tasks.

            $null values and empty or whitespace-only strings are dropped, so an unbound
            task parameter never shadows an environment variable. That is what makes the
            'parameters override environment variables' rule safe: only a value the caller
            actually supplied ever takes precedence.

        .PARAMETER InputObject
            The parameter table. $null returns an empty hashtable. Any IDictionary is
            accepted, including [ordered] dictionaries.

        .EXAMPLE
            ConvertFrom-EnterpriseRepositoryParameterTable -InputObject @{
                EnterpriseSmbShare   = '\\FS01\PowerShellRepo'
                EnterpriseCredential = $credential
            }

            Returns @{ SmbShare = '\\FS01\PowerShellRepo'; Credential = $credential }.

        .OUTPUTS
            System.Collections.Hashtable
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Position = 0)]
        [AllowNull()]
        [System.Object]
        $InputObject
    )

    $resolvedSetting = @{}

    if ($null -eq $InputObject)
    {
        return $resolvedSetting
    }

    if ($InputObject -isnot [System.Collections.IDictionary])
    {
        throw (
            'The enterprise repository parameter table must be a hashtable, but a ' +
            "'$($InputObject.GetType().FullName)' was supplied. Example: " +
            "./build.ps1 -Tasks build, publish-enterprise -Parameters @{ EnterpriseSmbShare = '\\FS01\PowerShellRepo' }"
        )
    }

    foreach ($entry in $InputObject.GetEnumerator())
    {
        $suppliedKey = [System.String] $entry.Key
        $canonicalName = $null

        foreach ($aliasEntry in $script:EnterpriseRepositoryParameterAlias.GetEnumerator())
        {
            # -contains is case-insensitive, matching PowerShell parameter binding.
            if ($aliasEntry.Value -contains $suppliedKey)
            {
                $canonicalName = $aliasEntry.Key

                break
            }
        }

        if ($null -eq $canonicalName)
        {
            Write-Verbose -Message "Ignoring '$suppliedKey': not an enterprise repository setting."

            continue
        }

        $value = $entry.Value

        if ($null -eq $value)
        {
            continue
        }

        if ($value -is [System.String] -and [string]::IsNullOrWhiteSpace($value))
        {
            continue
        }

        if ($canonicalName -eq 'Credential' -and $value -isnot [System.Management.Automation.PSCredential])
        {
            throw (
                "The enterprise repository parameter '$suppliedKey' must be a " +
                "System.Management.Automation.PSCredential, but a '$($value.GetType().FullName)' " +
                "was supplied. Example: EnterpriseCredential = (Get-Credential 'CORP\svc_psrepo')"
            )
        }

        $resolvedSetting[$canonicalName] = $value
    }

    return $resolvedSetting
}

function Resolve-EnterpriseRepositorySetting
{
    <#
        .SYNOPSIS
            Applies the 'parameter wins over environment variable' precedence to a single
            string setting.

        .DESCRIPTION
            Returns the parameter value when the caller supplied a non-empty one, then the
            process environment variable, then $null. Whitespace-only values count as not
            supplied, which is what makes an unbound Invoke-Build property (resolved to an
            empty string by 'property Name ""') transparent.

        .PARAMETER ParameterValue
            The value supplied as a build parameter. May be $null or empty.

        .PARAMETER EnvironmentVariableName
            Name of the ENTERPRISE_REPO_* environment variable used as the fallback.

        .EXAMPLE
            Resolve-EnterpriseRepositorySetting -ParameterValue $SmbShare -EnvironmentVariableName 'ENTERPRISE_REPO_SMB_SHARE'

            Returns the parameter when set, otherwise the environment variable.

        .OUTPUTS
            System.String
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Position = 0)]
        [AllowNull()]
        [AllowEmptyString()]
        [System.String]
        $ParameterValue,

        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $EnvironmentVariableName
    )

    if (-not [string]::IsNullOrWhiteSpace($ParameterValue))
    {
        Write-Verbose -Message "Resolved from a build parameter, overriding '$EnvironmentVariableName' if it is set."

        return $ParameterValue.Trim()
    }

    $environmentValue = [System.Environment]::GetEnvironmentVariable($EnvironmentVariableName)

    if (-not [string]::IsNullOrWhiteSpace($environmentValue))
    {
        Write-Verbose -Message "Resolved from the environment variable '$EnvironmentVariableName'."

        return $environmentValue.Trim()
    }

    return $null
}

function Get-EnterpriseRepositoryConfiguration
{
    <#
        .SYNOPSIS
            Builds the enterprise repository publishing configuration from build
            parameters and the environment.

        .DESCRIPTION
            Resolves every setting used by the 'Publish_Module_To_EnterpriseRepository'
            build task, honouring this precedence for each individual setting:

                build parameter > process environment variable > local '.env' file > default

            Because precedence is applied per setting, a caller can pass only the
            credential as a parameter and keep the share in the environment, or the other
            way round. The returned object reports whether the task is enabled, which is
            driven exclusively by the presence of an SMB share, so that a build without
            enterprise configuration simply skips the task.

            SECURITY
            Passing -Credential is the preferred interactive path: the secret stays inside
            the PowerShell process as a SecureString and never reaches the process
            environment, the command line, the shell history or a log. The
            ENTERPRISE_REPO_PASSWORD variable remains supported only because CI/CD secret
            stores have no other injection mechanism.

        .PARAMETER LocalConfigurationPath
            Optional path to a local '.env' style file used to seed the environment on a
            developer workstation. Values already in the environment take precedence, and
            build parameters take precedence over both.

        .PARAMETER SmbShare
            Optional explicit UNC path overriding ENTERPRISE_REPO_SMB_SHARE, for example
            '\\FS01\PowerShellRepo'. This is the master switch of the whole task.

        .PARAMETER Credential
            Optional PSCredential used to authenticate against the share, overriding every
            other credential source (SecretManagement secret, user name and password
            variables).

        .PARAMETER CredentialSecretName
            Optional name of a SecretManagement secret, overriding
            ENTERPRISE_REPO_CREDENTIAL.

        .PARAMETER VaultName
            Optional SecretManagement vault name, overriding ENTERPRISE_REPO_VAULT.

        .PARAMETER UserName
            Optional user name such as 'CORP\svc_psrepo', overriding
            ENTERPRISE_REPO_USERNAME. Combined with ENTERPRISE_REPO_PASSWORD, or with a
            SecureString secret read from the vault.

        .PARAMETER ModulePath
            Optional explicit path to the built module folder, overriding
            ENTERPRISE_REPO_MODULE_PATH and the automatic
            'output/<sub>/<name>/<version>' discovery.

        .PARAMETER DryRun
            Optional dry-run flag overriding ENTERPRISE_REPO_WHATIF. Accepts a
            [System.Boolean], a [System.Management.Automation.SwitchParameter] or any of
            the strings '1', 'true', 'yes', 'y', 'on' (case-insensitive).

        .EXAMPLE
            Get-EnterpriseRepositoryConfiguration -LocalConfigurationPath './.enterprise-repo.env'

            Returns the resolved configuration for a build driven entirely by the
            environment and the local configuration file.

        .EXAMPLE
            $configurationParam = @{
                SmbShare   = '\\FS01\PowerShellRepo'
                Credential = (Get-Credential -UserName 'CORP\svc_psrepo' -Message 'Enterprise repository')
            }
            Get-EnterpriseRepositoryConfiguration @configurationParam

            Returns a configuration where both the share and the credential were supplied
            as parameters, ignoring any ENTERPRISE_REPO_SMB_SHARE already exported.

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
        [Alias('EnterpriseSmbShare')]
        [AllowNull()]
        [AllowEmptyString()]
        [System.String]
        $SmbShare,

        [Parameter()]
        [Alias('EnterpriseCredential')]
        [AllowNull()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter()]
        [Alias('EnterpriseCredentialSecretName')]
        [AllowNull()]
        [AllowEmptyString()]
        [System.String]
        $CredentialSecretName,

        [Parameter()]
        [Alias('EnterpriseVaultName')]
        [AllowNull()]
        [AllowEmptyString()]
        [System.String]
        $VaultName,

        [Parameter()]
        [Alias('EnterpriseUserName')]
        [AllowNull()]
        [AllowEmptyString()]
        [System.String]
        $UserName,

        [Parameter()]
        [Alias('EnterpriseModulePath')]
        [AllowNull()]
        [AllowEmptyString()]
        [System.String]
        $ModulePath,

        [Parameter()]
        [Alias('EnterpriseDryRun')]
        [AllowNull()]
        [System.Object]
        $DryRun
    )

    if (-not [string]::IsNullOrWhiteSpace($LocalConfigurationPath))
    {
        $null = Import-EnterpriseRepositoryEnvFile -Path $LocalConfigurationPath
    }

    $variableName = $script:EnterpriseRepositoryEnvironmentVariable

    $resolvedShare = Resolve-EnterpriseRepositorySetting -ParameterValue $SmbShare -EnvironmentVariableName $variableName.SmbShare

    if (-not [string]::IsNullOrWhiteSpace($resolvedShare))
    {
        # Normalise so that Path.Combine() never produces a double separator.
        $resolvedShare = $resolvedShare.TrimEnd('\', '/')
    }

    <#
        A dry-run flag passed as a parameter wins, including when it is explicitly $false,
        so an operator can force a real publication on an agent where
        ENTERPRISE_REPO_WHATIF is exported.
    #>
    $isWhatIf = if ($PSBoundParameters.ContainsKey('DryRun') -and $null -ne $DryRun)
    {
        Test-EnterpriseRepositoryTruthyValue -Value $DryRun
    }
    else
    {
        Test-EnterpriseRepositoryTruthyValue -Value ([System.Environment]::GetEnvironmentVariable($variableName.WhatIf))
    }

    return @{
        IsEnabled            = -not [string]::IsNullOrWhiteSpace($resolvedShare)
        SmbShare             = $resolvedShare
        Credential           = $Credential
        CredentialSecretName = (Resolve-EnterpriseRepositorySetting -ParameterValue $CredentialSecretName -EnvironmentVariableName $variableName.CredentialName)
        VaultName            = (Resolve-EnterpriseRepositorySetting -ParameterValue $VaultName -EnvironmentVariableName $variableName.VaultName)
        UserName             = (Resolve-EnterpriseRepositorySetting -ParameterValue $UserName -EnvironmentVariableName $variableName.UserName)
        ModulePath           = (Resolve-EnterpriseRepositorySetting -ParameterValue $ModulePath -EnvironmentVariableName $variableName.ModulePath)
        WhatIf               = $isWhatIf
    }
}

function Resolve-EnterpriseRepositoryCredential
{
    <#
        .SYNOPSIS
            Resolves the PSCredential used to authenticate against the SMB repository.

        .DESCRIPTION
            Supports three credential sources, in order of preference:

            1. A PSCredential supplied as a build parameter, for example
               './build.ps1 -Parameters @{ EnterpriseCredential = (Get-Credential) }'.
               This is the only source where the secret never leaves the PowerShell
               process.
            2. A SecretManagement secret, named by the CredentialSecretName setting
               (parameter or ENTERPRISE_REPO_CREDENTIAL), holding either a PSCredential or
               a SecureString (the latter requires a user name).
            3. The UserName setting plus ENTERPRISE_REPO_PASSWORD, which is the pattern
               used by CI/CD secret injection (GitHub Secrets, Azure DevOps).

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

    <#
        A credential passed as a build parameter outranks every other source: the operator
        was explicit, and the secret is already a SecureString inside this process.
    #>
    $explicitCredential = $Configuration['Credential']

    if ($null -ne $explicitCredential)
    {
        if ($explicitCredential -isnot [System.Management.Automation.PSCredential])
        {
            throw (
                'The enterprise repository credential must be a ' +
                "System.Management.Automation.PSCredential, but a '$($explicitCredential.GetType().FullName)' " +
                "was supplied. Example: -Parameters @{ EnterpriseCredential = (Get-Credential 'CORP\svc_psrepo') }"
            )
        }

        Write-Verbose -Message (
            "Using the PSCredential supplied as a build parameter ('$($explicitCredential.UserName)'); " +
            'SecretManagement and ENTERPRISE_REPO_USERNAME/PASSWORD are ignored.'
        )

        return $explicitCredential
    }

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

function Get-EnterpriseRepositoryCredentialSource
{
    <#
        .SYNOPSIS
            Describes, without disclosing any secret, where the repository credential came
            from.

        .DESCRIPTION
            Produces a short label used in the build transcript so an operator can confirm
            which precedence branch was taken. Only the resolution path and the user name
            are reported; the password is never touched.

        .PARAMETER Configuration
            The hashtable returned by Get-EnterpriseRepositoryConfiguration.

        .EXAMPLE
            Get-EnterpriseRepositoryCredentialSource -Configuration $configuration

            Returns 'Build parameter (PSCredential)' when a credential was supplied
            through './build.ps1 -Parameters @{ EnterpriseCredential = ... }'.

        .OUTPUTS
            System.String
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [System.Collections.Hashtable]
        $Configuration
    )

    if ($null -ne $Configuration['Credential'])
    {
        return 'build parameter (PSCredential)'
    }

    if (-not [string]::IsNullOrWhiteSpace($Configuration['CredentialSecretName']))
    {
        return "SecretManagement secret '$($Configuration['CredentialSecretName'])'"
    }

    $password = [System.Environment]::GetEnvironmentVariable(
        $script:EnterpriseRepositoryEnvironmentVariable.Password
    )

    if (-not [string]::IsNullOrWhiteSpace($Configuration['UserName']) -and -not [string]::IsNullOrWhiteSpace($password))
    {
        return 'ENTERPRISE_REPO_USERNAME / ENTERPRISE_REPO_PASSWORD'
    }

    return 'build agent security context'
}

function Get-EnterpriseRepositorySecretCredential
{
    <#
        .SYNOPSIS
            Reads the repository credential from a SecretManagement vault.

        .DESCRIPTION
            Retrieves the secret named by the CredentialSecretName setting (parameter or
            ENTERPRISE_REPO_CREDENTIAL) and converts it into a PSCredential. A PSCredential
            secret is returned as is; a SecureString secret is combined with the UserName
            setting. Returns $null only when the SecretManagement module is absent and the
            caller explicitly allows falling back to the user name and password
            environment variables.

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
                'ENTERPRISE_REPO_USERNAME/ENTERPRISE_REPO_PASSWORD fallback was provided. ' +
                'Pass a credential instead: -Parameters @{ EnterpriseCredential = (Get-Credential) }'
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
                'be supplied through ENTERPRISE_REPO_USERNAME or the EnterpriseUserName ' +
                'build parameter.'
            )
        }

        return [System.Management.Automation.PSCredential]::new($Configuration['UserName'], $secret)
    }

    throw (
        "The secret '$secretName' is of unsupported type '$($secret.GetType().FullName)'. " +
        'Store a PSCredential or a SecureString.'
    )
}
