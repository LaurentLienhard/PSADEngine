function New-ADSiteLink {
    <#
    .SYNOPSIS
        Instantiates dedicated IP Site Links connecting branch sites to a target Hub site.
    .DESCRIPTION
        This Tier 0 automation cmdlet creates explicit siteLink objects within the Active Directory
        Configuration Naming Context (CN=Inter-Site Transports,CN=IP,CN=Sites,CN=Configuration,...).
        It connects remote branch sites directly to a designated Hub site to enable Netlogon Auto-Site Coverage
        and enforce deterministic DC Locator routing.
    .PARAMETER HubSiteName
        The Relative Distinguished Name (RDN) of the primary Hub site hosting active Domain Controllers.
    .PARAMETER TargetBranchSites
        An array of branch site RDNs to link directly with the specified Hub site.
    .PARAMETER NamingFormat
        The naming convention format for created siteLink objects.
        Supported placeholders: {Hub} and {Branch}. Default format is "Lien {Hub}-{Branch}".
    .PARAMETER Cost
        The inter-site replication cost assigned to the site links. Default is 100.
    .PARAMETER ReplicationFrequencyInMinutes
        Replication interval in minutes. Default is 15.
    .EXAMPLE
        New-ADSiteLink -HubSiteName "HUB1" -TargetBranchSites @("BRANCH1", "BRANCH2") -WhatIf
    .EXAMPLE
        New-ADSiteLink -HubSiteName "HUB1" -TargetBranchSites @("BRANCH1", "BRANCH2") -NamingFormat "{Hub}-TO-{Branch}" -Cost 50 -Verbose
    .OUTPUTS
        PSCustomObject containing implementation status and created object details.
    .NOTES
        Author: Senior Identity & Directory Services Architect
        Requirement: ActiveDirectory Module (RSAT), Enterprise Admins / Tier 0 Privileges
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$HubSiteName,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string[]]$TargetBranchSites,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$NamingFormat = "Lien {Hub}-{Branch}",

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$Cost = 100,

        [Parameter(Mandatory = $false)]
        [ValidateRange(15, 10080)]
        [int]$ReplicationFrequencyInMinutes = 15
    )

    begin {
        if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
            Throw "The ActiveDirectory RSAT module is required to execute this cmdlet."
        }

        # Retrieve the Configuration Naming Context dynamically
        try {
            [string]$ConfigNC = (Get-ADRootDSE -ErrorAction Stop).configurationNamingContext
        }
        catch {
            Throw "Failed to query RootDSE to resolve Configuration Naming Context: $_"
        }

        [string]$SitesContainerDN = "CN=Sites,$ConfigNC"
        Write-Verbose "Configuration NC resolved: $ConfigNC"
    }

    process {
        # Validate Hub Site existence in the Configuration Partition
        [string]$HubSiteDN = "CN=$HubSiteName,$SitesContainerDN"
        if (-not (Get-ADObject -Identity $HubSiteDN -ErrorAction SilentlyContinue)) {
            Write-Error "Target Hub site '$HubSiteName' ($HubSiteDN) does not exist in the Configuration Partition. Skipping hub processing."
            return
        }

        foreach ($BranchSiteName in $TargetBranchSites) {
            [string]$BranchSiteDN = "CN=$BranchSiteName,$SitesContainerDN"

            # Construct dynamic SiteLink name based on NamingFormat pattern
            [string]$SiteLinkName = $NamingFormat -replace '\{Hub\}', $HubSiteName -replace '\{Branch\}', $BranchSiteName

            # Validate Branch Site existence
            if (-not (Get-ADObject -Identity $BranchSiteDN -ErrorAction SilentlyContinue)) {
                Write-Warning "Branch site '$BranchSiteName' ($BranchSiteDN) does not exist in Active Directory. Skipping."

                [PSCustomObject]@{
                    SiteLinkName      = $SiteLinkName
                    HubSite           = $HubSiteName
                    BranchSite        = $BranchSiteName
                    Status            = "Skipped"
                    Reason            = "Branch site object missing"
                    DistinguishedName = $null
                }
                continue
            }

            [string[]]$SitesToInclude = @($HubSiteDN, $BranchSiteDN)

            if ($PSCmdlet.ShouldProcess($SiteLinkName, "Create/Align IP Site Link connecting '$HubSiteName' and '$BranchSiteName'")) {
                try {
                    $ExistingLink = Get-ADReplicationSiteLink -Filter "Name -eq '$SiteLinkName'" -ErrorAction SilentlyContinue

                    if (-not $ExistingLink) {
                        $NewLink = New-ADReplicationSiteLink -Name $SiteLinkName `
                                                            -SitesIncluded $SitesToInclude `
                                                            -Cost $Cost `
                                                            -ReplicationFrequencyInMinutes $ReplicationFrequencyInMinutes `
                                                            -Description "Dedicated Regional Site Link connecting $BranchSiteName to $HubSiteName Hub" `
                                                            -PassThru `
                                                            -ErrorAction Stop

                        Write-Verbose "Successfully created Site Link object: $($NewLink.DistinguishedName)"

                        [PSCustomObject]@{
                            SiteLinkName      = $SiteLinkName
                            HubSite           = $HubSiteName
                            BranchSite        = $BranchSiteName
                            Status            = "Created"
                            Reason            = "New siteLink object instantiated"
                            Cost              = $Cost
                            ReplIntervalMin   = $ReplicationFrequencyInMinutes
                            DistinguishedName = $NewLink.DistinguishedName
                        }
                    }
                    else {
                        Set-ADReplicationSiteLink -Identity $SiteLinkName `
                                                  -SitesIncluded $SitesToInclude `
                                                  -Cost $Cost `
                                                  -ReplicationFrequencyInMinutes $ReplicationFrequencyInMinutes `
                                                  -ErrorAction Stop

                        Write-Verbose "Successfully updated Site Link object: $($ExistingLink.DistinguishedName)"

                        [PSCustomObject]@{
                            SiteLinkName      = $SiteLinkName
                            HubSite           = $HubSiteName
                            BranchSite        = $BranchSiteName
                            Status            = "Updated"
                            Reason            = "Existing siteLink object updated"
                            Cost              = $Cost
                            ReplIntervalMin   = $ReplicationFrequencyInMinutes
                            DistinguishedName = $ExistingLink.DistinguishedName
                        }
                    }
                }
                catch {
                    Write-Error "Failed to process Site Link '$SiteLinkName': $_"
                    [PSCustomObject]@{
                        SiteLinkName      = $SiteLinkName
                        HubSite           = $HubSiteName
                        BranchSite        = $BranchSiteName
                        Status            = "Failed"
                        Reason            = $_.Exception.Message
                        DistinguishedName = $null
                    }
                }
            }
        }
    }

    end {
        Write-Verbose "Site Link instantiation phase completed."
    }
}
