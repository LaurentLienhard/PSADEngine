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

        function script:New-TestCredential
        {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
            param ([string]$UserName = 'CORP\adm_jsmith')

            return [System.Management.Automation.PSCredential]::new(
                $UserName,
                (ConvertTo-SecureString -String 'Placeholder-Value-01!' -AsPlainText -Force))
        }
    }

    Describe 'Get-PSADTokenGroupSidFromDirectory' {
        Context 'When the platform is not Windows' -Skip:$script:isWindowsPlatform {
            It 'Should throw a PlatformNotSupportedException' {
                $exception = { Get-PSADTokenGroupSidFromDirectory -Credential (script:New-TestCredential) } |
                    Should -Throw -PassThru

                $exception.Exception.GetType().FullName | Should -Be 'System.PlatformNotSupportedException'
            }

            It 'Should fail before attempting any directory bind' {
                { Get-PSADTokenGroupSidFromDirectory -Credential (script:New-TestCredential) -Server 'DC01.corp.contoso.com' } |
                    Should -Throw -ExpectedMessage '*System.DirectoryServices is not functional*'
            }
        }

        Context 'Parameter contract' {
            It 'Should require a credential' {
                (Get-Command -Name 'Get-PSADTokenGroupSidFromDirectory').Parameters['Credential'].Attributes.Where({
                        $_ -is [System.Management.Automation.ParameterAttribute]
                    }).Mandatory | Should -Contain $true
            }

            It 'Should type Credential as PSCredential' {
                (Get-Command -Name 'Get-PSADTokenGroupSidFromDirectory').Parameters['Credential'].ParameterType |
                    Should -Be ([System.Management.Automation.PSCredential])
            }

            It 'Should guard the credential with ValidateNotNull' {
                <#
                    Binding $null is not exercised directly: the Credential transformation
                    attribute would raise an interactive credential prompt, which would hang a
                    non interactive build agent.
                #>
                (Get-Command -Name 'Get-PSADTokenGroupSidFromDirectory').Parameters['Credential'].Attributes |
                    Should -Contain ([System.Management.Automation.ValidateNotNullAttribute]::new())
            }

            It 'Should allow the server to be omitted so the client locator is used' {
                $serverAttribute = (Get-Command -Name 'Get-PSADTokenGroupSidFromDirectory').Parameters['Server'].Attributes.Where({
                        $_ -is [System.Management.Automation.ParameterAttribute]
                    })

                $serverAttribute.Mandatory | Should -Not -Contain $true
            }
        }

        Context 'Implementation choices' {
            BeforeAll {
                <#
                    These assertions inspect the abstract syntax tree rather than the raw
                    source text. A regular expression over the source would also match the
                    comment based help, which documents the very constructs being forbidden.
                #>
                $script:ast = (Get-Command -Name 'Get-PSADTokenGroupSidFromDirectory').ScriptBlock.Ast

                $script:literal = @(
                    $script:ast.FindAll(
                        { $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true) |
                        ForEach-Object -Process { $_.Value }
                )

                $script:invokedCommand = @(
                    $script:ast.FindAll(
                        { $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true) |
                        ForEach-Object -Process { $_.GetCommandName() }
                )
            }

            It 'Should read the constructed tokenGroups attribute' {
                $script:literal | Should -Contain 'tokenGroups'
            }

            It 'Should not walk memberOf, which misses nesting and primary group membership' {
                $script:literal | Should -Not -Contain 'memberOf'
            }

            It 'Should escape both values placed into the LDAP filter' {
                @($script:invokedCommand).Where({ 'Format-PSADLdapFilterValue' -eq $_ }).Count |
                    Should -BeGreaterOrEqual 2
            }

            It 'Should dispose every directory handle in a finally block' {
                $tryWithFinally = @(
                    $script:ast.FindAll(
                        {
                            $args[0] -is [System.Management.Automation.Language.TryStatementAst] -and
                            $null -ne $args[0].Finally
                        }, $true)
                )

                $tryWithFinally.Count | Should -BeGreaterThan 0
                $tryWithFinally[0].Finally.Extent.Text | Should -Match 'Dispose'
            }

            It 'Should not place SearchResult in the disposal list because it is not IDisposable' {
                $finallyText = @(
                    $script:ast.FindAll(
                        {
                            $args[0] -is [System.Management.Automation.Language.TryStatementAst] -and
                            $null -ne $args[0].Finally
                        }, $true)
                )[0].Finally.Extent.Text

                $finallyText | Should -Not -Match 'searchResult'
                $finallyText | Should -Match 'rootEntry'
            }

            It 'Should not declare a Windows only type in a catch clause' {
                <#
                    PowerShell resolves catch clause types when the script block is compiled.
                    A typed catch on System.DirectoryServices would turn module import into a
                    parse error on any non Windows host, including a cross platform build agent.
                #>
                $catchType = @(
                    $script:ast.FindAll(
                        { $args[0] -is [System.Management.Automation.Language.CatchClauseAst] }, $true) |
                        ForEach-Object -Process { $_.CatchTypes } |
                        ForEach-Object -Process { $_.TypeName.FullName }
                )

                foreach ($typeName in $catchType)
                {
                    $typeName | Should -Not -Match 'DirectoryServices'
                }
            }
        }
    }
}
