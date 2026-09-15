BeforeDiscovery {
    Import-Module -Name 'PSADEngine' -Force
}

AfterAll {
    Get-Module -Name 'PSADEngine' -All | Remove-Module -Force
}

InModuleScope 'PSADEngine' {
    BeforeAll {
        $script:domainPrefix = 'S-1-5-21-1111111111-2222222222-3333333333'
    }

    Describe 'Test-PSADTier0Privilege' {
        Context 'When a Tier 0 group is present' {
            It 'Should match <Role> through relative identifier <Rid>' -ForEach @(
                @{ Rid = '512'; Role = 'Domain Admins' }
                @{ Rid = '519'; Role = 'Enterprise Admins' }
                @{ Rid = '518'; Role = 'Schema Admins' }
            ) {
                $sid = @("$script:domainPrefix-1105", "$script:domainPrefix-$Rid", "$script:domainPrefix-513")

                $result = Test-PSADTier0Privilege -SecurityIdentifier $sid

                $result.IsTier0 | Should -BeTrue
                $result.MatchedRole | Should -Be $Role
                $result.MatchedSid | Should -Be "$script:domainPrefix-$Rid"
            }

            It 'Should match regardless of the position in the collection' {
                $sid = @("$script:domainPrefix-512")

                (Test-PSADTier0Privilege -SecurityIdentifier $sid).IsTier0 | Should -BeTrue
            }

            It 'Should tolerate surrounding whitespace' {
                $sid = @("  $script:domainPrefix-512  ")

                (Test-PSADTier0Privilege -SecurityIdentifier $sid).IsTier0 | Should -BeTrue
            }
        }

        Context 'When no Tier 0 group is present' {
            It 'Should reject <Description>' -ForEach @(
                @{ Description = 'Domain Users only'; Sid = @('S-1-5-21-1111111111-2222222222-3333333333-513') }
                @{ Description = 'Authenticated Users'; Sid = @('S-1-5-11') }
                @{ Description = 'an ordinary user'; Sid = @('S-1-5-21-1111111111-2222222222-3333333333-1105') }
                @{ Description = 'an empty collection'; Sid = @() }
                @{ Description = 'a null collection'; Sid = $null }
                @{ Description = 'blank entries'; Sid = @('', '   ', $null) }
            ) {
                $result = Test-PSADTier0Privilege -SecurityIdentifier $Sid

                $result.IsTier0 | Should -BeFalse
                $result.MatchedRole | Should -BeNullOrEmpty
            }

            It 'Should not match a relative identifier that merely contains a Tier 0 value' {
                $sid = @("$script:domainPrefix-5120", "$script:domainPrefix-1512")

                (Test-PSADTier0Privilege -SecurityIdentifier $sid).IsTier0 | Should -BeFalse
            }

            It 'Should not match a malformed security identifier' {
                $sid = @('S-1-5-21-512', 'not-a-sid', 'S-1-5-21-a-b-c-512')

                (Test-PSADTier0Privilege -SecurityIdentifier $sid).IsTier0 | Should -BeFalse
            }
        }

        Context 'When BUILTIN\Administrators is the only privileged membership' {
            It 'Should reject it by default because the Enterprise Access Model requires a domain scoped role' {
                (Test-PSADTier0Privilege -SecurityIdentifier @('S-1-5-32-544')).IsTier0 | Should -BeFalse
            }

            It 'Should accept it when AllowBuiltinAdministrator is supplied' {
                $result = Test-PSADTier0Privilege -SecurityIdentifier @('S-1-5-32-544') -AllowBuiltinAdministrator

                $result.IsTier0 | Should -BeTrue
                $result.MatchedRole | Should -Be 'BUILTIN\Administrators'
            }
        }

        Context 'Result contract' {
            It 'Should count only the non blank identifiers it evaluated' {
                $result = Test-PSADTier0Privilege -SecurityIdentifier @('S-1-5-11', '', '   ', 'S-1-5-18')

                $result.EvaluatedSidCount | Should -Be 2
            }

            It 'Should require the SecurityIdentifier parameter' {
                (Get-Command -Name 'Test-PSADTier0Privilege').Parameters['SecurityIdentifier'].Attributes.Where({
                        $_ -is [System.Management.Automation.ParameterAttribute]
                    }).Mandatory | Should -Contain $true
            }
        }
    }
}
