<#
    .SYNOPSIS
        Artefact resolution, reachability and outcome helpers for the Invoke-Build task
        'Publish_Module_To_EnterpriseRepository'.

    .DESCRIPTION
        Locates the versioned module folder produced by ModuleBuilder, probes the target
        SMB share, classifies publishing failures and normalises the task outcome. The file
        contains no Invoke-Build 'task' statement so that Pester can dot-source it directly,
        and it has no dependency on the companion file
        './.build/EnterpriseRepository.Configuration.ps1'.

        It is auto-loaded by build.ps1, which dot-sources every '*.ps1' found under the
        './.build/' folder before the workflows declared in build.yaml are created.
#>

function Get-EnterpriseBuiltModuleBase
{
    <#
        .SYNOPSIS
            Resolves the folder that contains the per-module ModuleBuilder output folders.

        .DESCRIPTION
            The built module base is '<OutputDirectory>/<BuiltModuleSubdirectory>', but
            BuiltModuleSubdirectory is a build configuration value that is not always
            projected into an Invoke-Build property (build.ps1 keeps its own parameter
            default of an empty string). Rather than trusting a single source, this function
            probes the supplied candidates in priority order, then the Sampler default
            'module' folder, then the output directory itself, and returns the first
            candidate that actually contains a folder named after the project. When nothing
            matches, the highest priority candidate is returned so the caller raises a
            precise error.

        .PARAMETER OutputDirectory
            The build output directory, typically '<BuildRoot>/output'.

        .PARAMETER ProjectName
            The module name expected as a child folder of the built module base.

        .PARAMETER BuiltModuleSubdirectory
            Zero or more candidate subdirectory names, in priority order. Empty entries are
            ignored.

        .EXAMPLE
            Get-EnterpriseBuiltModuleBase -OutputDirectory './output' -ProjectName 'PSADEngine'

            Returns './output/module' when the module was built with the Sampler default layout.

        .OUTPUTS
            System.String
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $OutputDirectory,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ProjectName,

        [Parameter()]
        [AllowNull()]
        [System.String[]]
        $BuiltModuleSubdirectory
    )

    $candidate = [System.Collections.Generic.List[System.String]]::new()

    foreach ($subdirectory in (@($BuiltModuleSubdirectory) + @('module')))
    {
        if ([string]::IsNullOrWhiteSpace($subdirectory))
        {
            continue
        }

        $candidatePath = Join-Path -Path $OutputDirectory -ChildPath $subdirectory

        if (-not $candidate.Contains($candidatePath))
        {
            $candidate.Add($candidatePath)
        }
    }

    # ModuleBuilder can also emit straight into the output directory (no subdirectory).
    if (-not $candidate.Contains($OutputDirectory))
    {
        $candidate.Add($OutputDirectory)
    }

    foreach ($candidatePath in $candidate)
    {
        $probePath = Join-Path -Path $candidatePath -ChildPath $ProjectName

        if (Test-Path -Path $probePath -PathType Container)
        {
            Write-Verbose -Message "Resolved built module base to '$candidatePath'."

            return $candidatePath
        }
    }

    return $candidate[0]
}

function Resolve-EnterpriseModuleOutputPath
{
    <#
        .SYNOPSIS
            Resolves the versioned built module folder that must be published.

        .DESCRIPTION
            Determines the folder produced by ModuleBuilder, for example
            'output/module/PSADEngine/1.2.3'. An explicit path always wins; otherwise the
            version reported by the build (GitVersion) is used; otherwise the highest
            version folder found on disk is selected. The function throws when nothing can
            be resolved, because publishing a non-existent artefact must fail loudly.

        .PARAMETER BuiltModuleBase
            The folder containing the per-module output folders, typically
            '<OutputDirectory>/<BuiltModuleSubdirectory>'.

        .PARAMETER ProjectName
            The module name, used as the first folder level under the built module base.

        .PARAMETER ModuleVersion
            Optional module version calculated by the build pipeline.

        .PARAMETER ExplicitPath
            Optional explicit path to the built module folder, overriding all discovery.

        .EXAMPLE
            Resolve-EnterpriseModuleOutputPath -BuiltModuleBase './output/module' -ProjectName 'PSADEngine'

            Returns the highest version folder of the built module.

        .OUTPUTS
            System.String
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $BuiltModuleBase,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ProjectName,

        [Parameter()]
        [System.String]
        $ModuleVersion,

        [Parameter()]
        [System.String]
        $ExplicitPath
    )

    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath))
    {
        if (-not (Test-Path -Path $ExplicitPath))
        {
            throw "The module output path '$ExplicitPath' does not exist. Run './build.ps1 -Tasks build' first."
        }

        return (Resolve-Path -Path $ExplicitPath).Path
    }

    $moduleRoot = Join-Path -Path $BuiltModuleBase -ChildPath $ProjectName

    if (-not (Test-Path -Path $moduleRoot -PathType Container))
    {
        throw "The built module folder '$moduleRoot' does not exist. Run './build.ps1 -Tasks build' first."
    }

    if (-not [string]::IsNullOrWhiteSpace($ModuleVersion))
    {
        # GitVersion returns SemVer values such as '1.2.3-preview0001'; the output folder only uses the numeric part.
        $versionFolderName = ($ModuleVersion -split '-')[0]
        $versionedPath = Join-Path -Path $moduleRoot -ChildPath $versionFolderName

        if (Test-Path -Path (Join-Path -Path $versionedPath -ChildPath "$ProjectName.psd1"))
        {
            return (Resolve-Path -Path $versionedPath).Path
        }

        Write-Verbose -Message "No manifest under '$versionedPath'; falling back to on-disk version discovery."
    }

    $candidate = Get-ChildItem -Path $moduleRoot -Directory -ErrorAction Stop |
        Where-Object -FilterScript {
            Test-Path -Path (Join-Path -Path $_.FullName -ChildPath "$ProjectName.psd1")
        } |
        Sort-Object -Property {
            $parsedVersion = [version] '0.0.0'

            if ([version]::TryParse($_.Name, [ref] $parsedVersion))
            {
                $parsedVersion
            }
            else
            {
                [version] '0.0.0'
            }
        } -Descending |
        Select-Object -First 1

    if ($null -eq $candidate)
    {
        throw "No versioned module manifest '$ProjectName.psd1' found under '$moduleRoot'. Run './build.ps1 -Tasks build' first."
    }

    return $candidate.FullName
}

function Test-EnterpriseRepositoryReachable
{
    <#
        .SYNOPSIS
            Tests whether the SMB repository share can be reached with the current context.

        .DESCRIPTION
            Performs a non-throwing container test against the UNC path. This pre-flight
            check is only meaningful when no explicit credential is used, because an
            authenticated SMB session is established by Publish-EnterpriseBypassModule
            itself. A negative result is treated as a soft failure by the build task.

        .PARAMETER SmbShare
            UNC path of the enterprise repository share, for example '\\FS01\PowerShellRepo'.

        .EXAMPLE
            Test-EnterpriseRepositoryReachable -SmbShare '\\FS01\PowerShellRepo'

            Returns $true when the share is browsable by the current build identity.

        .OUTPUTS
            System.Boolean
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $SmbShare
    )

    try
    {
        return [bool] (Test-Path -Path $SmbShare -PathType Container -ErrorAction Stop)
    }
    catch
    {
        Write-Verbose -Message "Reachability probe for '$SmbShare' failed: $($_.Exception.Message)"

        return $false
    }
}

function Get-EnterpriseRepositoryFailureKind
{
    <#
        .SYNOPSIS
            Classifies a publishing failure so the build task can decide to warn or fail.

        .DESCRIPTION
            Maps the message of a terminating error to one of three categories:
            'Authentication' for credential or permission problems (hard failure),
            'Unreachable' for transport and name resolution problems (soft failure that
            must not break a GitHub or PowerShell Gallery publication), and 'Unknown' for
            everything else, which is treated as a hard failure by the caller.

        .PARAMETER Message
            The exception message, ideally already unwrapped to the inner exception.

        .EXAMPLE
            Get-EnterpriseRepositoryFailureKind -Message 'The network path was not found'

            Returns 'Unreachable'.

        .OUTPUTS
            System.String
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [System.String]
        $Message
    )

    $authenticationPattern = @(
        'access is denied'
        'access denied'
        'logon failure'
        'unauthorized'
        'user name or password'
        'bad username or password'
        'password has expired'
        'account is locked'
        'not permitted to log on'
        'system error 1326'
        'system error 5 '
        '0x8009030c'
    )

    $unreachablePattern = @(
        'network path was not found'
        'network name cannot be found'
        'bad network name'
        'network is unreachable'
        'no such host is known'
        'network location cannot be reached'
        'system error 53'
        'system error 64'
        'system error 67'
        'rpc server is unavailable'
        'did not respond'
        'timed out'
        'timeout'
        'is not accessible'
    )

    foreach ($pattern in $authenticationPattern)
    {
        if ($Message -match [regex]::Escape($pattern))
        {
            return 'Authentication'
        }
    }

    foreach ($pattern in $unreachablePattern)
    {
        if ($Message -match [regex]::Escape($pattern))
        {
            return 'Unreachable'
        }
    }

    return 'Unknown'
}

function New-EnterpriseRepositoryPublishResult
{
    <#
        .SYNOPSIS
            Builds the status object returned by the enterprise publishing build task.

        .DESCRIPTION
            Normalises the outcome of the task into a single object so every exit path -
            skipped, dry run, degraded, succeeded or failed - reports the same shape. The
            object is stored by the task in the build scope variable
            $EnterpriseRepositoryPublishResult, where a downstream task or a CI/CD step can
            inspect it.

        .PARAMETER Status
            Outcome of the task: Succeeded, DryRun, Skipped, Degraded or Failed.

        .PARAMETER ModuleName
            Name of the module that was, or should have been, published.

        .PARAMETER ModulePath
            Path to the built module folder used as the publishing source.

        .PARAMETER TargetSmbPath
            UNC path of the enterprise repository share that was targeted.

        .PARAMETER Reason
            Human readable explanation, mainly used for the Skipped, Degraded and Failed
            outcomes.

        .PARAMETER FailureKind
            Classification returned by Get-EnterpriseRepositoryFailureKind, or None.

        .PARAMETER Detail
            Optional raw payload returned by Publish-EnterpriseBypassModule.

        .EXAMPLE
            New-EnterpriseRepositoryPublishResult -Status 'Skipped' -Reason 'Share not configured'

            Returns a normalised status object describing a skipped publication.

        .OUTPUTS
            System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingVerbs', '',
        Justification = 'The function only creates an in-memory object and changes no system state.'
    )]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Succeeded', 'DryRun', 'Skipped', 'Degraded', 'Failed')]
        [System.String]
        $Status,

        [Parameter()]
        [System.String]
        $ModuleName,

        [Parameter()]
        [System.String]
        $ModulePath,

        [Parameter()]
        [System.String]
        $TargetSmbPath,

        [Parameter()]
        [System.String]
        $Reason,

        [Parameter()]
        [ValidateSet('None', 'Authentication', 'Unreachable', 'Unknown')]
        [System.String]
        $FailureKind = 'None',

        [Parameter()]
        [AllowNull()]
        [System.Object]
        $Detail
    )

    return [PSCustomObject]@{
        Task          = 'Publish_Module_To_EnterpriseRepository'
        Status        = $Status
        IsPublished   = ($Status -eq 'Succeeded')
        IsBuildFatal  = ($Status -eq 'Failed')
        ModuleName    = $ModuleName
        ModulePath    = $ModulePath
        TargetSmbPath = $TargetSmbPath
        Reason        = $Reason
        FailureKind   = $FailureKind
        Detail        = $Detail
        Timestamp     = (Get-Date)
    }
}
