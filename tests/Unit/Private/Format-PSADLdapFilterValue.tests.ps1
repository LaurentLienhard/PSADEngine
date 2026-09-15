BeforeDiscovery {
    Import-Module -Name 'PSADEngine' -Force
}

AfterAll {
    Get-Module -Name 'PSADEngine' -All | Remove-Module -Force
}

InModuleScope 'PSADEngine' {
    Describe 'Format-PSADLdapFilterValue' {
        Context 'When the value contains no metacharacter' {
            It 'Should return <Value> unchanged' -ForEach @(
                @{ Value = 'jdoe' }
                @{ Value = 'adm_jsmith' }
                @{ Value = 'svc_app01' }
                @{ Value = 'jdoe@corp.contoso.com' }
                @{ Value = 'CORP\adm_jsmith'; Expected = 'CORP\5cadm_jsmith' }
            ) {
                $expected = if ($null -ne $Expected) { $Expected } else { $Value }

                Format-PSADLdapFilterValue -Value $Value | Should -Be $expected
            }
        }

        Context 'When the value contains RFC 4515 metacharacters' {
            It 'Should escape <Description>' -ForEach @(
                @{ Description = 'an asterisk'; Value = '*'; Expected = '\2a' }
                @{ Description = 'an opening parenthesis'; Value = '('; Expected = '\28' }
                @{ Description = 'a closing parenthesis'; Value = ')'; Expected = '\29' }
                @{ Description = 'a backslash'; Value = '\'; Expected = '\5c' }
                @{ Description = 'a NUL'; Value = "`0"; Expected = '\00' }
            ) {
                Format-PSADLdapFilterValue -Value $Value | Should -Be $Expected
            }

            It 'Should escape the backslash first so escape sequences are not double escaped' {
                # A naive implementation would turn '*' into '\2a' then the backslash into '\5c2a'.
                Format-PSADLdapFilterValue -Value '\*' | Should -Be '\5c\2a'
            }

            It 'Should neutralise an injected filter component' {
                $injection = 'svc_app01)(objectClass=*'

                $result = Format-PSADLdapFilterValue -Value $injection

                $result | Should -Be 'svc_app01\29\28objectClass=\2a'
                $result | Should -Not -Match '[()*]'
            }

            It 'Should neutralise an always true injection' {
                $result = Format-PSADLdapFilterValue -Value '*)(|(sAMAccountName=*'

                $result | Should -Not -Match '[()*]'
            }
        }

        Context 'When the value is empty' {
            It 'Should return an empty string' {
                Format-PSADLdapFilterValue -Value '' | Should -Be ([System.String]::Empty)
            }
        }

        Context 'When values arrive over the pipeline' {
            It 'Should process every element' {
                $result = @('jdoe', '*' | Format-PSADLdapFilterValue)

                $result | Should -Be @('jdoe', '\2a')
            }
        }
    }
}
