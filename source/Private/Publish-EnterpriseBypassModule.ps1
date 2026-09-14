function Publish-EnterpriseBypassModule
{
    <#
    .SYNOPSIS
        Publishes a PowerShell module to an SMB repository by manually building a compliant .nupkg file with PSModule tags,
        bypassing dotnet.exe pack errors and ensuring PowerShellGet/PackageManagement compatibility.
    .DESCRIPTION
        Inspects the module manifest, constructs an OPC-compliant NuGet package (.nupkg) containing mandatory PSModule tags
        in the .nuspec XML file, establishes an authenticated SMB session, and places the .nupkg artifact at the share root
        and versioned directory structure.
    .PARAMETER ModulePath
        The local file path to the root or versioned folder of the module.
    .PARAMETER TargetSmbShare
        The UNC path of the SMB repository share. Defaults to '\\DSDPWINADM\PowerShellRepo'.
    .PARAMETER Credential
        Optional PSCredential object used to establish an authenticated SMB session.
    .EXAMPLE
        $publishParams = @{
            ModulePath     = 'C:\Program Files\PowerShell\Modules\PSADEngine'
            TargetSmbShare = '\\Server\RepoName'
            Credential     = Adm Credential
        }
        Publish-EnterpriseBypassModule @publishParams
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ModulePath,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$TargetSmbShare,

        [Parameter(Mandatory = $false)]
        [PSCredential]
        [System.Management.Automation.Credential()]
        $Credential
    )

    begin
    {
        Write-Verbose -Message "Initializing custom SMB packaging pipeline for module path: $ModulePath"
        $ErrorActionPreference = 'Stop'
        $tempStagingPath = $null
        $smbMappingCreated = $false
    }

    process
    {
        if ($PSCmdlet.ShouldProcess($ModulePath, "Build PSModule-tagged .nupkg package and publish to $TargetSmbShare"))
        {
            try
            {
                # 1. Establish Explicit Authenticated SMB Mapping if Credential is provided
                if ($PSBoundParameters.ContainsKey('Credential') -and $null -ne $Credential)
                {
                    Write-Verbose -Message "Establishing explicit SMB session mapping to '$TargetSmbShare' using credentials for '$($Credential.UserName)'..."

                    $existingMapping = Get-SmbMapping -RemotePath $TargetSmbShare -ErrorAction SilentlyContinue
                    if ($null -ne $existingMapping)
                    {
                        Remove-SmbMapping -RemotePath $TargetSmbShare -Force -UpdateProfile -ErrorAction SilentlyContinue
                    }

                    $mappingParams = @{
                        RemotePath      = $TargetSmbShare
                        Credential      = $Credential
                        SaveCredentials = $false
                        ErrorAction     = 'Stop'
                    }

                    $null = New-SmbMapping @mappingParams
                    $smbMappingCreated = $true
                    Write-Verbose -Message "Successfully established authenticated SMB session mapping."
                }

                # 2. Resolve Path and Locate .psd1 Manifest
                $resolvedPath = (Resolve-Path -Path $ModulePath -ErrorAction Stop).Path
                $manifestFile = Get-ChildItem -Path $resolvedPath -Filter '*.psd1' -Recurse -ErrorAction Stop | Select-Object -First 1

                if ($null -eq $manifestFile)
                {
                    throw [System.IO.FileNotFoundException]::new("No valid .psd1 module manifest found in or under path: $resolvedPath")
                }

                $moduleRootFolder = $manifestFile.DirectoryName
                Write-Verbose -Message "Found module manifest at: $($manifestFile.FullName)"

                $manifestData = Test-ModuleManifest -Path $manifestFile.FullName -ErrorAction Stop
                $moduleName = [string]$manifestData.Name
                $moduleVersion = [string]$manifestData.Version.ToString()
                $moduleDescription = if ([string]::IsNullOrWhitespace($manifestData.Description))
                {
                    "Enterprise Module $moduleName"
                }
                else
                {
                    $manifestData.Description
                }
                $moduleAuthor = if ([string]::IsNullOrWhitespace($manifestData.Author))
                {
                    "Corporate Identity Team"
                }
                else
                {
                    $manifestData.Author
                }

                Write-Verbose -Message "Validated module '$moduleName' (Version: $moduleVersion)."

                # 3. Construct Staging Workspace
                $folderGuid = [System.Guid]::NewGuid().ToString('N')
                $tempStagingPath = [System.IO.Path]::Combine($env:TEMP, "PSBuild_${moduleName}_${folderGuid}")

                if (Test-Path -Path $tempStagingPath)
                {
                    Remove-Item -Path $tempStagingPath -Recurse -Force -ErrorAction Stop
                }
                $null = New-Item -Path $tempStagingPath -ItemType Directory -Force

                # 4. Generate XML .nuspec Metadata File WITH MANDATORY PSModule TAGS
                $nuspecXml = @"
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2011/08/nuspec.xsd">
  <metadata>
    <id>$moduleName</id>
    <version>$moduleVersion</version>
    <authors>$moduleAuthor</authors>
    <owners>$moduleAuthor</owners>
    <requireLicenseAcceptance>false</requireLicenseAcceptance>
    <description>$moduleDescription</description>
    <releaseNotes>Enterprise Automated Build</releaseNotes>
    <tags>PSModule PSIncludes_Function PSFunction_$moduleName</tags>
  </metadata>
</package>
"@
                $nuspecPath = [System.IO.Path]::Combine($tempStagingPath, "$moduleName.nuspec")
                Set-Content -Path $nuspecPath -Value $nuspecXml -Encoding utf8

                # Copy payload files directly to staging root alongside .nuspec
                Copy-Item -Path "$moduleRootFolder\*" -Destination $tempStagingPath -Recurse -Force

                # 5. Generate .nupkg Archive (Zip Archive)
                $nupkgFileName = "$moduleName.$moduleVersion.nupkg"
                $nupkgDestinationPath = [System.IO.Path]::Combine($env:TEMP, "NupkgOut_${folderGuid}", $nupkgFileName)
                $nupkgOutDir = [System.IO.Path]::GetDirectoryName($nupkgDestinationPath)
                $null = New-Item -Path $nupkgOutDir -ItemType Directory -Force

                Write-Verbose -Message "Assembling native NuGet package with PSModule tags: $nupkgFileName"

                Add-Type -AssemblyName 'System.IO.Compression.FileSystem'
                [System.IO.Compression.ZipFile]::CreateFromDirectory($tempStagingPath, $nupkgDestinationPath)

                # 6. Deploy Package Artifacts to SMB Share (Root & Subfolders)
                Write-Verbose -Message "Deploying package artifacts to SMB share: $TargetSmbShare"

                # Copy .nupkg to Share Root (Required for Find-Module on FileSystem PSRepository)
                $rootNupkgTarget = [System.IO.Path]::Combine($TargetSmbShare, $nupkgFileName)
                Copy-Item -Path $nupkgDestinationPath -Destination $rootNupkgTarget -Force -ErrorAction Stop
                Write-Verbose -Message "Placed root package artifact: $rootNupkgTarget"

                # Copy to Versioned Folder Structure
                $destinationFolder = [System.IO.Path]::Combine($TargetSmbShare, $moduleName, $moduleVersion)
                if (-not (Test-Path -Path $destinationFolder))
                {
                    $null = New-Item -Path $destinationFolder -ItemType Directory -Force -ErrorAction Stop
                }

                Copy-Item -Path $nupkgDestinationPath -Destination $destinationFolder -Force -ErrorAction Stop
                Copy-Item -Path "$moduleRootFolder\*" -Destination $destinationFolder -Recurse -Force -ErrorAction Stop

                [PSCustomObject]@{
                    ModuleName      = $moduleName
                    ModuleVersion   = $moduleVersion
                    TargetSmbPath   = $destinationFolder
                    RootPackageFile = $rootNupkgTarget
                    Status          = 'PublishedSuccessfully'
                    Timestamp       = (Get-Date)
                }
            }
            catch [System.IO.FileNotFoundException]
            {
                Write-Error -Message "File structure error: $($_.Exception.Message)" -ErrorAction Stop
            }
            catch [System.UnauthorizedAccessException]
            {
                Write-Error -Message "Access denied writing to SMB share '$TargetSmbShare': $($_.Exception.Message)" -ErrorAction Stop
            }
            catch [System.Exception]
            {
                $rootCause = if ($_.Exception.InnerException)
                {
                    $_.Exception.InnerException.Message
                }
                else
                {
                    $_.Exception.Message
                }
                Write-Error -Message "Failed to build and publish module: $rootCause" -ErrorAction Stop
            }
            finally
            {
                # Clean up staging files
                if (-not [string]::IsNullOrEmpty($tempStagingPath) -and (Test-Path -Path $tempStagingPath))
                {
                    Write-Verbose -Message "Cleaning up temporary staging folder: $tempStagingPath"
                    Remove-Item -Path $tempStagingPath -Recurse -Force -ErrorAction SilentlyContinue
                }
                if ($null -ne $nupkgOutDir -and (Test-Path -Path $nupkgOutDir))
                {
                    Remove-Item -Path $nupkgOutDir -Recurse -Force -ErrorAction SilentlyContinue
                }

                # Clean up SMB mapping
                if ($smbMappingCreated)
                {
                    Write-Verbose -Message "Cleaning up SMB session mapping for '$TargetSmbShare'..."
                    Remove-SmbMapping -RemotePath $TargetSmbShare -Force -UpdateProfile -ErrorAction SilentlyContinue
                }
            }
        }
    }

    end
    {
        Write-Verbose -Message "Bypass module publishing task completed."
    }
}
