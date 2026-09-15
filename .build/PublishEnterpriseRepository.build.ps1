<#
    .SYNOPSIS
        Invoke-Build task publishing the built PSADEngine module to an internal SMB
        PowerShell repository.

    .DESCRIPTION
        Adds the task 'Publish_Module_To_EnterpriseRepository' to the build pipeline. The
        task wraps the private function Publish-EnterpriseBypassModule, which assembles an
        OPC compliant .nupkg carrying the mandatory PSModule tags and copies it to the
        share root and to the versioned folder structure expected by a FileSystem
        PSRepository.

        DISCOVERY
        build.ps1 dot-sources every '*.ps1' file found under './.build/' after importing
        the task aliases declared in build.yaml (ModuleBuildTasks). Dropping this file in
        './.build/' is therefore all that is required for the task to be available; the
        ModuleBuildTasks section is reserved for tasks shipped inside a module such as
        Sampler or Sampler.GitHubTasks.

        The task logic lives in two companion files loaded the same way, kept separate so
        that Pester can dot-source them without triggering any 'task' statement:
          ./.build/EnterpriseRepository.Configuration.ps1  (settings and credentials)
          ./.build/EnterpriseRepository.Publication.ps1    (artefact, probe, outcome)

        Publish-EnterpriseBypassModule is a PRIVATE module function, therefore not exported
        by the built module. The task dot-sources it straight from
        './source/Private/' so the publication never depends on the module being imported.

        CONFIGURATION (environment variables)
        ENTERPRISE_REPO_SMB_SHARE   Mandatory switch of the whole task. UNC path of the
                                    repository share, e.g. '\\FS01\PowerShellRepo'. When
                                    it is not defined the task logs and returns, so a
                                    build without enterprise configuration never fails.
        ENTERPRISE_REPO_CREDENTIAL  Optional name of a SecretManagement secret holding a
                                    PSCredential (or a SecureString, combined with
                                    ENTERPRISE_REPO_USERNAME).
        ENTERPRISE_REPO_VAULT       Optional SecretManagement vault name.
        ENTERPRISE_REPO_USERNAME    Optional user name, e.g. 'CORP\svc_psrepo'.
        ENTERPRISE_REPO_PASSWORD    Optional password, injected from GitHub Secrets or an
                                    Azure DevOps secret variable. Never store it on disk.
        ENTERPRISE_REPO_MODULE_PATH Optional explicit path to the built module folder,
                                    overriding the automatic 'output/<sub>/<name>/<version>'
                                    discovery.
        ENTERPRISE_REPO_WHATIF      Optional. Set to 'true' for a dry run that validates
                                    configuration, credentials and paths without writing.

        A developer workstation can place the non-secret values in a git-ignored
        './.enterprise-repo.env' file; see './.enterprise-repo.env.example'. Process
        environment variables always take precedence over that file.

        FAILURE SEMANTICS
        Module folder missing          -> hard failure (the artefact must exist).
        Credential declared but broken -> hard failure with an explicit message.
        Authentication or access denied-> hard failure with an explicit message.
        Share unreachable or timed out -> warning only; the build keeps its GitHub and
                                          PowerShell Gallery publications.
        Non-Windows build agent        -> warning only; SMB mapping cmdlets are Windows
                                          only, so use a 'windows-latest' runner.

        IDEMPOTENCY
        Re-running the task republishes the same version over itself. The underlying
        function copies with -Force and creates the versioned folder only when missing, so
        repeated runs converge on the same state.

    .EXAMPLE
        ./build.ps1 -Tasks publish

        Publishes the GitHub release, the wiki content, the PowerShell Gallery package and
        finally the enterprise SMB repository.

    .EXAMPLE
        ./build.ps1 -Tasks build, publish-enterprise

        Builds the module and publishes it to the enterprise SMB repository only.

    .NOTES
        Tier 0 note: an internal PowerShell repository is a software supply chain asset.
        Restrict write access on the share to a dedicated build service account, and audit
        it like any other Tier 0 adjacent resource.
#>

param
(
    [Parameter()]
    [System.String]
    $ProjectName = (property ProjectName ''),

    [Parameter()]
    [System.String]
    $SourcePath = (property SourcePath ''),

    [Parameter()]
    [System.String]
    $OutputDirectory = (property OutputDirectory (Join-Path -Path $BuildRoot -ChildPath 'output')),

    [Parameter()]
    [System.String]
    $BuiltModuleSubdirectory = (property BuiltModuleSubdirectory ''),

    [Parameter()]
    [System.String]
    $ModuleVersion = (property ModuleVersion ''),

    # Typed as Object on purpose: the YAML deserializer may return a Hashtable or an
    # ordered dictionary, and a hard type constraint would break the dot-sourcing.
    [Parameter()]
    [AllowNull()]
    [System.Object]
    $BuildInfo = (property BuildInfo @{}),

    [Parameter()]
    [System.String]
    $ModuleOutputPath = (property ModuleOutputPath ''),

    [Parameter()]
    [System.String]
    $EnterpriseRepositorySmbShare = (property EnterpriseRepositorySmbShare ''),

    [Parameter()]
    [System.String]
    $EnterpriseRepositoryConfigFile = (property EnterpriseRepositoryConfigFile '.enterprise-repo.env')
)

# Synopsis: Publishes the built module to the enterprise SMB PowerShell repository (skipped when ENTERPRISE_REPO_SMB_SHARE is not defined).
task Publish_Module_To_EnterpriseRepository {
    $ErrorActionPreference = 'Stop'

    $taskName = 'Publish_Module_To_EnterpriseRepository'

    # ------------------------------------------------------------------ #
    # 1. Resolve build context                                            #
    # ------------------------------------------------------------------ #
    if ([string]::IsNullOrWhiteSpace($ProjectName))
    {
        $ProjectName = if (Get-Command -Name 'Get-SamplerProjectName' -ErrorAction SilentlyContinue)
        {
            Get-SamplerProjectName -BuildRoot $BuildRoot
        }
        else
        {
            Split-Path -Path $BuildRoot -Leaf
        }
    }

    if ([string]::IsNullOrWhiteSpace($SourcePath))
    {
        $SourcePath = if (Get-Command -Name 'Get-SamplerSourcePath' -ErrorAction SilentlyContinue)
        {
            Get-SamplerSourcePath -BuildRoot $BuildRoot
        }
        else
        {
            Join-Path -Path $BuildRoot -ChildPath 'source'
        }
    }

    if ([string]::IsNullOrWhiteSpace($OutputDirectory))
    {
        $OutputDirectory = Join-Path -Path $BuildRoot -ChildPath 'output'
    }
    elseif (-not (Split-Path -Path $OutputDirectory -IsAbsolute))
    {
        $OutputDirectory = Join-Path -Path $BuildRoot -ChildPath $OutputDirectory
    }

    # ------------------------------------------------------------------ #
    # 2. Resolve configuration and decide whether the task applies        #
    # ------------------------------------------------------------------ #
    $configurationParam = @{
        LocalConfigurationPath = Join-Path -Path $BuildRoot -ChildPath $EnterpriseRepositoryConfigFile
        SmbShare               = $EnterpriseRepositorySmbShare
    }

    $configuration = Get-EnterpriseRepositoryConfiguration @configurationParam

    if (-not $configuration.IsEnabled)
    {
        Write-Build Yellow "  $taskName skipped: ENTERPRISE_REPO_SMB_SHARE is not defined."

        $notConfiguredResultParam = @{
            Status     = 'Skipped'
            ModuleName = $ProjectName
            Reason     = 'ENTERPRISE_REPO_SMB_SHARE is not defined.'
        }

        $script:EnterpriseRepositoryPublishResult = New-EnterpriseRepositoryPublishResult @notConfiguredResultParam

        return
    }

    <#
        Windows PowerShell 5.1 does not define $IsWindows at all, so the variable is read
        indirectly to stay compatible with Set-StrictMode.
    #>
    $isWindowsHost = $true
    $windowsIndicator = Get-Variable -Name 'IsWindows' -ValueOnly -ErrorAction SilentlyContinue

    if ($null -ne $windowsIndicator)
    {
        $isWindowsHost = [System.Boolean] $windowsIndicator
    }

    if (-not $isWindowsHost)
    {
        Write-Build Yellow "  $taskName skipped: SMB publishing requires a Windows build agent."

        $skippedResultParam = @{
            Status        = 'Skipped'
            ModuleName    = $ProjectName
            TargetSmbPath = $configuration.SmbShare
            Reason        = 'SMB publishing requires a Windows build agent (New-SmbMapping is Windows only).'
        }

        $script:EnterpriseRepositoryPublishResult = New-EnterpriseRepositoryPublishResult @skippedResultParam

        return
    }

    Write-Build DarkGray "  Target SMB repository : $($configuration.SmbShare)"

    # ------------------------------------------------------------------ #
    # 3. Resolve the artefact (hard failure when missing)                 #
    # ------------------------------------------------------------------ #
    <#
        BuiltModuleSubdirectory is declared in build.yaml, but build.ps1 owns a parameter
        of the same name whose default is empty, so the Invoke-Build property can resolve
        to '' even when the configuration says 'module'. Both sources are therefore offered
        to the resolver, which probes the file system before deciding.
    #>
    $subdirectoryCandidate = @($BuiltModuleSubdirectory)

    if ($BuildInfo -is [System.Collections.IDictionary] -and $BuildInfo['BuiltModuleSubdirectory'])
    {
        $subdirectoryCandidate += [System.String] $BuildInfo['BuiltModuleSubdirectory']
    }

    $builtModuleBaseParam = @{
        OutputDirectory         = $OutputDirectory
        ProjectName             = $ProjectName
        BuiltModuleSubdirectory = $subdirectoryCandidate
    }

    $builtModuleBase = Get-EnterpriseBuiltModuleBase @builtModuleBaseParam

    $explicitModulePath = $ModuleOutputPath

    if ([string]::IsNullOrWhiteSpace($explicitModulePath))
    {
        $explicitModulePath = $configuration.ModulePath
    }

    $modulePathParam = @{
        BuiltModuleBase = $builtModuleBase
        ProjectName     = $ProjectName
        ModuleVersion   = $ModuleVersion
        ExplicitPath    = $explicitModulePath
    }

    $resolvedModulePath = Resolve-EnterpriseModuleOutputPath @modulePathParam

    Write-Build DarkGray "  Module artefact       : $resolvedModulePath"

    # ------------------------------------------------------------------ #
    # 4. Resolve credentials (hard failure when declared but broken)      #
    # ------------------------------------------------------------------ #
    $credential = Resolve-EnterpriseRepositoryCredential -Configuration $configuration

    if ($null -ne $credential)
    {
        Write-Build DarkGray "  Authenticating as     : $($credential.UserName)"
    }
    else
    {
        Write-Build DarkGray '  Authenticating as     : build agent security context'

        <#
            The pre-flight probe is only meaningful without an explicit credential;
            Publish-EnterpriseBypassModule establishes its own authenticated SMB session
            when a credential is supplied.
        #>
        if (-not (Test-EnterpriseRepositoryReachable -SmbShare $configuration.SmbShare))
        {
            Write-Warning -Message (
                "The enterprise repository share '$($configuration.SmbShare)' is not " +
                'reachable from this build agent. The module was NOT published to the ' +
                'enterprise repository; other publication targets are unaffected.'
            )

            Write-Build Yellow "  $taskName degraded: share unreachable."

            $degradedResultParam = @{
                Status        = 'Degraded'
                ModuleName    = $ProjectName
                ModulePath    = $resolvedModulePath
                TargetSmbPath = $configuration.SmbShare
                Reason        = 'The share did not answer the pre-flight reachability probe.'
                FailureKind   = 'Unreachable'
            }

            $script:EnterpriseRepositoryPublishResult = New-EnterpriseRepositoryPublishResult @degradedResultParam

            return
        }
    }

    # ------------------------------------------------------------------ #
    # 5. Load the private packaging function                              #
    # ------------------------------------------------------------------ #
    $privateFunctionPath = Join-Path -Path $SourcePath -ChildPath 'Private' |
        Join-Path -ChildPath 'Publish-EnterpriseBypassModule.ps1'

    if (-not (Test-Path -Path $privateFunctionPath -PathType Leaf))
    {
        throw "Unable to locate the packaging function at '$privateFunctionPath'."
    }

    . $privateFunctionPath

    # ------------------------------------------------------------------ #
    # 6. Publish                                                          #
    # ------------------------------------------------------------------ #
    $publishParam = @{
        ModulePath     = $resolvedModulePath
        TargetSmbShare = $configuration.SmbShare
        Confirm        = $false
        ErrorAction    = 'Stop'
    }

    if ($null -ne $credential)
    {
        $publishParam['Credential'] = $credential
    }

    if ($configuration.WhatIf)
    {
        Write-Build Yellow '  ENTERPRISE_REPO_WHATIF is set: performing a dry run.'

        $publishParam['WhatIf'] = $true
    }

    try
    {
        $publishResult = Publish-EnterpriseBypassModule @publishParam

        $publishStatus = 'Succeeded'

        if ($configuration.WhatIf)
        {
            $publishStatus = 'DryRun'
        }

        $successResultParam = @{
            Status        = $publishStatus
            ModuleName    = $ProjectName
            ModulePath    = $resolvedModulePath
            TargetSmbPath = $configuration.SmbShare
            Detail        = $publishResult
        }

        $script:EnterpriseRepositoryPublishResult = New-EnterpriseRepositoryPublishResult @successResultParam

        Write-Build Green "  Module published to the enterprise repository: $($configuration.SmbShare)"
    }
    catch
    {
        $rootCause = if ($_.Exception.InnerException)
        {
            $_.Exception.InnerException.Message
        }
        else
        {
            $_.Exception.Message
        }

        $failureKind = Get-EnterpriseRepositoryFailureKind -Message $rootCause

        $failureStatus = 'Failed'

        if ($failureKind -eq 'Unreachable')
        {
            # Transport failures must not invalidate the GitHub and Gallery publications.
            $failureStatus = 'Degraded'
        }

        $failureResultParam = @{
            Status        = $failureStatus
            ModuleName    = $ProjectName
            ModulePath    = $resolvedModulePath
            TargetSmbPath = $configuration.SmbShare
            Reason        = $rootCause
            FailureKind   = $failureKind
        }

        $script:EnterpriseRepositoryPublishResult = New-EnterpriseRepositoryPublishResult @failureResultParam

        if ($failureKind -eq 'Unreachable')
        {
            Write-Warning -Message (
                "The enterprise repository share '$($configuration.SmbShare)' could not " +
                "be reached: $rootCause. The module was NOT published to the enterprise " +
                'repository; other publication targets are unaffected.'
            )

            Write-Build Yellow "  $taskName degraded: share unreachable."

            return
        }

        if ($failureKind -eq 'Authentication')
        {
            throw (
                "Authentication or authorisation failure against the enterprise " +
                "repository '$($configuration.SmbShare)': $rootCause. Verify " +
                'ENTERPRISE_REPO_CREDENTIAL / ENTERPRISE_REPO_USERNAME / ' +
                'ENTERPRISE_REPO_PASSWORD and the share level permissions of the build ' +
                'service account.'
            )
        }

        throw "Failed to publish '$ProjectName' to '$($configuration.SmbShare)': $rootCause"
    }
}
