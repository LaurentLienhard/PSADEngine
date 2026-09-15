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

        Context 'Operator feedback' {
            BeforeAll {
                $script:feedbackListener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
                $script:feedbackListener.Start()
                $script:feedbackPort = $script:feedbackListener.LocalEndpoint.Port
            }

            AfterAll {
                if ($null -ne $script:feedbackListener)
                {
                    $script:feedbackListener.Stop()
                }
            }

            It 'Should narrate the probe before it is attempted' {
                $connectivityParam = @{
                    ComputerName        = '127.0.0.1'
                    Port                = $script:feedbackPort
                    TimeoutMilliseconds = 5000
                }

                $verbose = Test-PSADLdapConnectivity @connectivityParam -Verbose 4>&1 | Out-String

                $verbose | Should -Match 'Opening a TCP probe'
                $verbose | Should -Match '5000 ms budget'
            }

            It 'Should report the elapsed connection time against the budget' {
                $connectivityParam = @{
                    ComputerName        = '127.0.0.1'
                    Port                = $script:feedbackPort
                    TimeoutMilliseconds = 5000
                }

                $verbose = Test-PSADLdapConnectivity @connectivityParam -Verbose 4>&1 | Out-String

                $verbose | Should -Match 'returned True after \d+ ms of a 5000 ms budget'
            }

            It 'Should report the elapsed time on an unreachable target as well' {
                $probe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
                $probe.Start()
                $closedPort = $probe.LocalEndpoint.Port
                $probe.Stop()

                $connectivityParam = @{
                    ComputerName        = '127.0.0.1'
                    Port                = $closedPort
                    TimeoutMilliseconds = 2000
                }

                $verbose = Test-PSADLdapConnectivity @connectivityParam -Verbose 4>&1 | Out-String

                $verbose | Should -Match 'returned False after \d+ ms'
            }

            It 'Should still return only a boolean on the success stream' {
                $connectivityParam = @{
                    ComputerName        = '127.0.0.1'
                    Port                = $script:feedbackPort
                    TimeoutMilliseconds = 5000
                }

                $result = Test-PSADLdapConnectivity @connectivityParam -Verbose

                $result | Should -BeOfType [bool]
                $result | Should -BeTrue
            }
        }
    }
}
