<#
    .SYNOPSIS
        Unit tests for the artefact, reachability and outcome helpers backing the
        Invoke-Build task 'Publish_Module_To_EnterpriseRepository'.

    .DESCRIPTION
        The helpers live in ./.build/EnterpriseRepository.Publication.ps1 and are
        dot-sourced here directly, which is possible because that file contains no
        Invoke-Build 'task' statement. Every file system interaction is confined to
        $TestDrive; no SMB share is contacted.
#>

BeforeAll {
    $script:projectPath = "$($PSScriptRoot)/../../.." | Convert-Path

    $script:helperPath = Join-Path -Path $script:projectPath -ChildPath '.build' |
        Join-Path -ChildPath 'EnterpriseRepository.Publication.ps1'

    . $script:helperPath
}

Describe 'Get-EnterpriseBuiltModuleBase' {
    BeforeAll {
        $script:outputDirectory = Join-Path -Path $TestDrive -ChildPath 'output'

        # Sampler default layout: output/module/<ProjectName>/<Version>
        $script:samplerBase = Join-Path -Path $script:outputDirectory -ChildPath 'module'

        $null = New-Item -ItemType Directory -Force -Path (
            Join-Path -Path $script:samplerBase -ChildPath 'PSADEngine'
        )
    }

    Context 'When the subdirectory is unknown to the Invoke-Build property' {
        It 'Should still discover the Sampler default module folder' {
            $baseParam = @{
                OutputDirectory         = $script:outputDirectory
                ProjectName             = 'PSADEngine'
                BuiltModuleSubdirectory = @('')
            }

            Get-EnterpriseBuiltModuleBase @baseParam | Should -BeExactly $script:samplerBase
        }
    }

    Context 'When the subdirectory is supplied explicitly' {
        It 'Should honour the supplied subdirectory' {
            $baseParam = @{
                OutputDirectory         = $script:outputDirectory
                ProjectName             = 'PSADEngine'
                BuiltModuleSubdirectory = @('module')
            }

            Get-EnterpriseBuiltModuleBase @baseParam | Should -BeExactly $script:samplerBase
        }
    }

    Context 'When no candidate contains the project folder' {
        It 'Should return the highest priority candidate so the caller can fail clearly' {
            $baseParam = @{
                OutputDirectory         = $script:outputDirectory
                ProjectName             = 'NotBuiltModule'
                BuiltModuleSubdirectory = @('custom')
            }

            Get-EnterpriseBuiltModuleBase @baseParam | Should -BeExactly (
                Join-Path -Path $script:outputDirectory -ChildPath 'custom'
            )
        }
    }
}

Describe 'Resolve-EnterpriseModuleOutputPath' {
    BeforeAll {
        $script:builtModuleBase = Join-Path -Path $TestDrive -ChildPath 'module'
        $script:moduleRoot = Join-Path -Path $script:builtModuleBase -ChildPath 'PSADEngine'

        foreach ($version in @('1.0.0', '1.2.0', '1.10.0'))
        {
            $versionFolder = Join-Path -Path $script:moduleRoot -ChildPath $version

            $null = New-Item -Path $versionFolder -ItemType Directory -Force
            $null = New-Item -Path (Join-Path -Path $versionFolder -ChildPath 'PSADEngine.psd1') -ItemType File -Force
        }
    }

    Context 'When an explicit path is supplied' {
        It 'Should return that path when it exists' {
            $expectedPath = Join-Path -Path $script:moduleRoot -ChildPath '1.2.0'

            $resolveParam = @{
                BuiltModuleBase = $script:builtModuleBase
                ProjectName     = 'PSADEngine'
                ExplicitPath    = $expectedPath
            }

            Resolve-EnterpriseModuleOutputPath @resolveParam |
                Should -BeExactly (Resolve-Path -Path $expectedPath).Path
        }

        It 'Should throw loudly when it does not exist' {
            $resolveParam = @{
                BuiltModuleBase = $script:builtModuleBase
                ProjectName     = 'PSADEngine'
                ExplicitPath    = (Join-Path -Path $TestDrive -ChildPath 'nowhere')
            }

            { Resolve-EnterpriseModuleOutputPath @resolveParam } |
                Should -Throw -ExpectedMessage '*does not exist*'
        }
    }

    Context 'When a module version is supplied by the pipeline' {
        It 'Should return the matching versioned folder' {
            $resolveParam = @{
                BuiltModuleBase = $script:builtModuleBase
                ProjectName     = 'PSADEngine'
                ModuleVersion   = '1.2.0'
            }

            Resolve-EnterpriseModuleOutputPath @resolveParam | Should -Match '1\.2\.0$'
        }

        It 'Should strip the prerelease label from a SemVer value' {
            $resolveParam = @{
                BuiltModuleBase = $script:builtModuleBase
                ProjectName     = 'PSADEngine'
                ModuleVersion   = '1.2.0-preview0001'
            }

            Resolve-EnterpriseModuleOutputPath @resolveParam | Should -Match '1\.2\.0$'
        }

        It 'Should fall back to discovery when the version folder is absent' {
            $resolveParam = @{
                BuiltModuleBase = $script:builtModuleBase
                ProjectName     = 'PSADEngine'
                ModuleVersion   = '9.9.9'
            }

            Resolve-EnterpriseModuleOutputPath @resolveParam | Should -Match '1\.10\.0$'
        }
    }

    Context 'When no version is supplied' {
        It 'Should select the highest version using numeric ordering' {
            $resolveParam = @{
                BuiltModuleBase = $script:builtModuleBase
                ProjectName     = 'PSADEngine'
            }

            Resolve-EnterpriseModuleOutputPath @resolveParam | Should -Match '1\.10\.0$'
        }
    }

    Context 'When the module was never built' {
        It 'Should throw and point at the build task' {
            $resolveParam = @{
                BuiltModuleBase = $script:builtModuleBase
                ProjectName     = 'NotBuiltModule'
            }

            { Resolve-EnterpriseModuleOutputPath @resolveParam } |
                Should -Throw -ExpectedMessage '*build.ps1 -Tasks build*'
        }
    }
}

Describe 'Test-EnterpriseRepositoryReachable' {
    Context 'When the path is a reachable container' {
        It 'Should return true' {
            Test-EnterpriseRepositoryReachable -SmbShare $TestDrive | Should -BeTrue
        }
    }

    Context 'When the path cannot be reached' {
        It 'Should return false instead of throwing' {
            $unreachablePath = Join-Path -Path $TestDrive -ChildPath 'no-such-share'

            Test-EnterpriseRepositoryReachable -SmbShare $unreachablePath | Should -BeFalse
        }
    }
}

Describe 'Get-EnterpriseRepositoryFailureKind' {
    It 'Should classify "<Message>" as <Expected>' -ForEach @(
        @{ Message = 'Access is denied writing to SMB share'; Expected = 'Authentication' }
        @{ Message = 'System error 1326 has occurred. Logon failure'; Expected = 'Authentication' }
        @{ Message = 'The network path was not found'; Expected = 'Unreachable' }
        @{ Message = 'System error 53 has occurred.'; Expected = 'Unreachable' }
        @{ Message = 'The operation has timed out'; Expected = 'Unreachable' }
        @{ Message = 'No valid .psd1 module manifest found'; Expected = 'Unknown' }
        @{ Message = ''; Expected = 'Unknown' }
    ) {
        Get-EnterpriseRepositoryFailureKind -Message $Message | Should -BeExactly $Expected
    }

    It 'Should prioritise authentication over transport classification' {
        $message = 'The network path was not found and access is denied'

        Get-EnterpriseRepositoryFailureKind -Message $message | Should -BeExactly 'Authentication'
    }
}

Describe 'New-EnterpriseRepositoryPublishResult' {
    Context 'When the publication succeeded' {
        It 'Should flag the result as published and not fatal' {
            $resultParam = @{
                Status        = 'Succeeded'
                ModuleName    = 'PSADEngine'
                TargetSmbPath = '\\FS01\PowerShellRepo'
            }

            $result = New-EnterpriseRepositoryPublishResult @resultParam

            $result.IsPublished | Should -BeTrue
            $result.IsBuildFatal | Should -BeFalse
            $result.FailureKind | Should -BeExactly 'None'
        }
    }

    Context 'When the share was unreachable' {
        It 'Should flag a degraded, non fatal result' {
            $resultParam = @{
                Status      = 'Degraded'
                ModuleName  = 'PSADEngine'
                Reason      = 'The network path was not found'
                FailureKind = 'Unreachable'
            }

            $result = New-EnterpriseRepositoryPublishResult @resultParam

            $result.IsPublished | Should -BeFalse
            $result.IsBuildFatal | Should -BeFalse
        }
    }

    Context 'When the publication failed' {
        It 'Should flag the result as fatal for the build' {
            $resultParam = @{
                Status      = 'Failed'
                ModuleName  = 'PSADEngine'
                Reason      = 'Access is denied'
                FailureKind = 'Authentication'
            }

            $result = New-EnterpriseRepositoryPublishResult @resultParam

            $result.IsBuildFatal | Should -BeTrue
            $result.Task | Should -BeExactly 'Publish_Module_To_EnterpriseRepository'
        }
    }

    Context 'When an unsupported status is supplied' {
        It 'Should reject it' {
            { New-EnterpriseRepositoryPublishResult -Status 'Whatever' } | Should -Throw
        }
    }
}
