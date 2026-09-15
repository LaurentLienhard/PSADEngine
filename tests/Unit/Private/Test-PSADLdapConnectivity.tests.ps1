BeforeDiscovery {
    Import-Module -Name 'PSADEngine' -Force
}

AfterAll {
    Get-Module -Name 'PSADEngine' -All | Remove-Module -Force
}

InModuleScope 'PSADEngine' {
    Describe 'Test-PSADLdapConnectivity' {
        Context 'When the target port is listening' {
            BeforeAll {
                <#
                    A loopback listener stands in for a domain controller LDAP endpoint so the
                    positive path is exercised for real rather than mocked away.
                #>
                $script:listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
                $script:listener.Start()
                $script:listeningPort = $script:listener.LocalEndpoint.Port
            }

            AfterAll {
                if ($null -ne $script:listener)
                {
                    $script:listener.Stop()
                }
            }

            It 'Should return true' {
                $connectivityParam = @{
                    ComputerName        = '127.0.0.1'
                    Port                = $script:listeningPort
                    TimeoutMilliseconds = 5000
                }

                Test-PSADLdapConnectivity @connectivityParam | Should -BeTrue
            }

            It 'Should return a boolean' {
                $connectivityParam = @{
                    ComputerName        = '127.0.0.1'
                    Port                = $script:listeningPort
                    TimeoutMilliseconds = 5000
                }

                Test-PSADLdapConnectivity @connectivityParam | Should -BeOfType [bool]
            }
        }

        Context 'When the target port is closed' {
            BeforeAll {
                # Bind then release so the port is almost certainly free.
                $probe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
                $probe.Start()
                $script:closedPort = $probe.LocalEndpoint.Port
                $probe.Stop()
            }

            It 'Should return false' {
                $connectivityParam = @{
                    ComputerName        = '127.0.0.1'
                    Port                = $script:closedPort
                    TimeoutMilliseconds = 2000
                }

                Test-PSADLdapConnectivity @connectivityParam | Should -BeFalse
            }

            It 'Should not throw' {
                $connectivityParam = @{
                    ComputerName        = '127.0.0.1'
                    Port                = $script:closedPort
                    TimeoutMilliseconds = 2000
                }

                { Test-PSADLdapConnectivity @connectivityParam } | Should -Not -Throw
            }
        }

        Context 'When the host name cannot be resolved' {
            It 'Should return false rather than throwing' {
                $connectivityParam = @{
                    ComputerName        = 'DC99.this-domain-does-not-resolve.invalid'
                    Port                = 389
                    TimeoutMilliseconds = 3000
                }

                Test-PSADLdapConnectivity @connectivityParam | Should -BeFalse
            }
        }

        Context 'Parameter contract' {
            It 'Should default to the LDAP port' {
                (Get-Command -Name 'Test-PSADLdapConnectivity').Parameters['Port'].Attributes.Where({
                        $_ -is [System.Management.Automation.ParameterAttribute]
                    }) | Should -Not -BeNullOrEmpty

                $default = (Get-Command -Name 'Test-PSADLdapConnectivity').ScriptBlock.Ast.Body.ParamBlock.Parameters.Where({
                        $_.Name.VariablePath.UserPath -eq 'Port'
                    }).DefaultValue.Extent.Text

                $default | Should -Be '389'
            }

            It 'Should reject an out of range port' {
                { Test-PSADLdapConnectivity -ComputerName '127.0.0.1' -Port 70000 } | Should -Throw
            }

            It 'Should reject an out of range timeout' {
                { Test-PSADLdapConnectivity -ComputerName '127.0.0.1' -Port 389 -TimeoutMilliseconds 1 } | Should -Throw
            }

            It 'Should reject an empty computer name' {
                { Test-PSADLdapConnectivity -ComputerName '' } | Should -Throw
            }
        }
    }
}
