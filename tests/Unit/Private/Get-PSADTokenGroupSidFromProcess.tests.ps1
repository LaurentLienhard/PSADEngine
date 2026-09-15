BeforeDiscovery {
    Import-Module -Name 'PSADEngine' -Force

    $script:isWindowsPlatform = ($PSVersionTable.PSVersion.Major -lt 6) -or $IsWindows
}

AfterAll {
    Get-Module -Name 'PSADEngine' -All | Remove-Module -Force
}

InModuleScope 'PSADEngine' {
    BeforeAll {
        $script:isWindowsPlatform = ($PSVersionTable.PSVersion.Major -lt 6) -or $IsWindows
    }

    Describe 'Get-PSADTokenGroupSidFromProcess' {
        Context 'When the platform is not Windows' -Skip:$script:isWindowsPlatform {
            It 'Should throw a PlatformNotSupportedException rather than returning an empty allow list' {
                $exception = { Get-PSADTokenGroupSidFromProcess } | Should -Throw -PassThru

                $exception.Exception.GetType().FullName | Should -Be 'System.PlatformNotSupportedException'
            }

            It 'Should never return an empty collection on an unsupported platform' {
                <#
                    This is the security critical assertion. Returning an empty collection
                    would make Test-PSADTier0Privilege evaluate to false, which fails closed,
                    but returning $null silently would risk a caller treating it as success.
                #>
                { Get-PSADTokenGroupSidFromProcess -ErrorAction Stop } | Should -Throw
            }
        }

        Context 'When running on Windows' -Skip:(-not $script:isWindowsPlatform) {
            It 'Should return at least one security identifier' {
                $result = Get-PSADTokenGroupSidFromProcess

                @($result).Count | Should -BeGreaterThan 0
            }

            It 'Should return well formed security identifier strings' {
                $result = Get-PSADTokenGroupSidFromProcess

                foreach ($sid in $result)
                {
                    $sid | Should -Match '^S-1-'
                }
            }

            It 'Should include the Everyone well known identity' {
                Get-PSADTokenGroupSidFromProcess | Should -Contain 'S-1-1-0'
            }

            It 'Should include the user security identifier as well as the groups' {
                $expected = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

                Get-PSADTokenGroupSidFromProcess | Should -Contain $expected
            }
        }

        Context 'Command contract' {
            It 'Should take no parameters beyond the common ones' {
                $parameters = (Get-Command -Name 'Get-PSADTokenGroupSidFromProcess').Parameters.Keys.Where({
                        $_ -notin [System.Management.Automation.PSCmdlet]::CommonParameters
                    })

                $parameters | Should -BeNullOrEmpty
            }

            It 'Should declare a string array output type' {
                (Get-Command -Name 'Get-PSADTokenGroupSidFromProcess').OutputType.Type |
                    Should -Contain ([System.String[]])
            }

            It 'Should dispose the WindowsIdentity handle in a finally block' {
                $ast = (Get-Command -Name 'Get-PSADTokenGroupSidFromProcess').ScriptBlock.Ast

                $tryWithFinally = @(
                    $ast.FindAll(
                        {
                            $args[0] -is [System.Management.Automation.Language.TryStatementAst] -and
                            $null -ne $args[0].Finally
                        }, $true)
                )

                $tryWithFinally.Count | Should -BeGreaterThan 0
                $tryWithFinally[0].Finally.Extent.Text | Should -Match 'windowsIdentity\.Dispose'
            }
        }

        Context 'Operator feedback' {
            It 'Should narrate that the access token is being enumerated' -Skip:(-not ($IsWindows -or $PSVersionTable.PSVersion.Major -lt 6)) {
                $verbose = Get-PSADTokenGroupSidFromProcess -Verbose 4>&1 | Out-String

                $verbose | Should -Match 'Enumerating the access token of the current process'
            }

            It 'Should narrate the collected count without narrating any identifier' -Skip:(-not ($IsWindows -or $PSVersionTable.PSVersion.Major -lt 6)) {
                $verbose = Get-PSADTokenGroupSidFromProcess -Verbose 4>&1 |
                    Where-Object { $_ -is [System.Management.Automation.VerboseRecord] } |
                    Out-String

                $verbose | Should -Match 'Collected \d+ security identifier'
                $verbose | Should -Not -Match 'S-1-5-21'
            }
        }
    }
}
