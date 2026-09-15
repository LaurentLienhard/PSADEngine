BeforeDiscovery {
    Import-Module -Name 'PSADEngine' -Force
}

AfterAll {
    Get-Module -Name 'PSADEngine' -All | Remove-Module -Force
}

InModuleScope 'PSADEngine' {
    BeforeAll {
        $script:processSid = @('S-1-5-21-1111111111-2222222222-3333333333-512', 'S-1-5-32-544')
        $script:directorySid = @('S-1-5-21-1111111111-2222222222-3333333333-519')

        function script:New-TestCredential
        {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '')]
            param ([string]$UserName)

            return [System.Management.Automation.PSCredential]::new(
                $UserName,
                (ConvertTo-SecureString -String 'Placeholder-Value-01!' -AsPlainText -Force))
        }
    }

    Describe 'Get-PSADTokenGroupSid' {
        BeforeEach {
            # A stale cache would make these assertions meaningless.
            $script:PSADTokenGroupSidCache = @{}

            Mock -CommandName Get-PSADTokenGroupSidFromProcess -MockWith { $script:processSid }
            Mock -CommandName Get-PSADTokenGroupSidFromDirectory -MockWith { $script:directorySid }
        }

        Context 'When no credential is supplied' {
            It 'Should read the access token of the current process' {
                $result = Get-PSADTokenGroupSid

                $result | Should -Be $script:processSid
                Should -Invoke -CommandName Get-PSADTokenGroupSidFromProcess -Exactly -Times 1 -Scope It
            }

            It 'Should not touch the directory' {
                $null = Get-PSADTokenGroupSid

                Should -Invoke -CommandName Get-PSADTokenGroupSidFromDirectory -Exactly -Times 0 -Scope It
            }
        }

        Context 'When a credential is supplied' {
            It 'Should read the transitive membership from the directory' {
                $result = Get-PSADTokenGroupSid -Credential (script:New-TestCredential -UserName 'CORP\adm_jsmith') -Server 'DC01.corp.contoso.com'

                $result | Should -Be $script:directorySid
                Should -Invoke -CommandName Get-PSADTokenGroupSidFromDirectory -Exactly -Times 1 -Scope It
            }

            It 'Should pass the server through to the directory collector' {
                $null = Get-PSADTokenGroupSid -Credential (script:New-TestCredential -UserName 'CORP\adm_jsmith') -Server 'DC01.corp.contoso.com'

                Should -Invoke -CommandName Get-PSADTokenGroupSidFromDirectory -Exactly -Times 1 -Scope It -ParameterFilter {
                    $Server -eq 'DC01.corp.contoso.com' -and $Credential.UserName -eq 'CORP\adm_jsmith'
                }
            }

            It 'Should fall back to the process token when the credential is the empty credential' {
                $null = Get-PSADTokenGroupSid -Credential ([System.Management.Automation.PSCredential]::Empty)

                Should -Invoke -CommandName Get-PSADTokenGroupSidFromProcess -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-PSADTokenGroupSidFromDirectory -Exactly -Times 0 -Scope It
            }
        }

        Context 'Credential caching for batch operations' {
            It 'Should evaluate the process token only once across repeated calls' {
                1..5 | ForEach-Object -Process { $null = Get-PSADTokenGroupSid }

                Should -Invoke -CommandName Get-PSADTokenGroupSidFromProcess -Exactly -Times 1 -Scope It
            }

            It 'Should return the same values from the cache' {
                $first = Get-PSADTokenGroupSid
                $second = Get-PSADTokenGroupSid

                $second | Should -Be $first
            }

            It 'Should evaluate each distinct credential once' {
                $adminOne = script:New-TestCredential -UserName 'CORP\adm_jsmith'
                $adminTwo = script:New-TestCredential -UserName 'CORP\adm_ajones'

                $null = Get-PSADTokenGroupSid -Credential $adminOne -Server 'DC01.corp.contoso.com'
                $null = Get-PSADTokenGroupSid -Credential $adminOne -Server 'DC01.corp.contoso.com'
                $null = Get-PSADTokenGroupSid -Credential $adminTwo -Server 'DC01.corp.contoso.com'

                Should -Invoke -CommandName Get-PSADTokenGroupSidFromDirectory -Exactly -Times 2 -Scope It
            }

            It 'Should key the cache on the server as well as the account' {
                $admin = script:New-TestCredential -UserName 'CORP\adm_jsmith'

                $null = Get-PSADTokenGroupSid -Credential $admin -Server 'DC01.corp.contoso.com'
                $null = Get-PSADTokenGroupSid -Credential $admin -Server 'DC02.corp.contoso.com'

                Should -Invoke -CommandName Get-PSADTokenGroupSidFromDirectory -Exactly -Times 2 -Scope It
            }

            It 'Should not share a cache entry between the process token and a credential' {
                $null = Get-PSADTokenGroupSid
                $null = Get-PSADTokenGroupSid -Credential (script:New-TestCredential -UserName 'CORP\adm_jsmith')

                Should -Invoke -CommandName Get-PSADTokenGroupSidFromProcess -Exactly -Times 1 -Scope It
                Should -Invoke -CommandName Get-PSADTokenGroupSidFromDirectory -Exactly -Times 1 -Scope It
            }

            It 'Should re-evaluate when Refresh is supplied so a membership change is picked up' {
                $null = Get-PSADTokenGroupSid
                $null = Get-PSADTokenGroupSid -Refresh
                $null = Get-PSADTokenGroupSid -Refresh

                Should -Invoke -CommandName Get-PSADTokenGroupSidFromProcess -Exactly -Times 3 -Scope It
            }
        }

        Context 'When the underlying collector fails' {
            It 'Should surface the failure rather than returning an empty allow list' {
                Mock -CommandName Get-PSADTokenGroupSidFromProcess -MockWith {
                    throw [System.PlatformNotSupportedException]::new('not windows')
                }

                { Get-PSADTokenGroupSid } | Should -Throw -ExpectedMessage '*not windows*'
            }

            It 'Should not cache a failed evaluation' {
                Mock -CommandName Get-PSADTokenGroupSidFromProcess -MockWith {
                    throw [System.PlatformNotSupportedException]::new('not windows')
                }

                { Get-PSADTokenGroupSid } | Should -Throw
                { Get-PSADTokenGroupSid } | Should -Throw

                Should -Invoke -CommandName Get-PSADTokenGroupSidFromProcess -Exactly -Times 2 -Scope It
            }
        }
    }
}
