function Get-PSADDomainHintFromIdentity
{
    <#
    .SYNOPSIS
        Derives the DNS domain name implied by a domain controller identity.

    .DESCRIPTION
        Extracts the DNS domain that a domain controller identity belongs to so that the
        domain controller inventory can be queried against the correct domain. Without this
        step a multi domain forest would always be searched against the domain of the
        management host, and a perfectly valid domain controller in a child domain would be
        rejected as unknown.

        Two derivations are supported, in priority order:

          1. Distinguished name. Every DC= component is collected in order and joined with
             dots, so 'CN=DC01,OU=Domain Controllers,DC=corp,DC=contoso,DC=com' yields
             'corp.contoso.com'. This is authoritative because it is what the directory
             itself stores.

          2. Fully qualified server name. Everything after the first label is used, so
             'DC01.corp.contoso.com' yields 'corp.contoso.com'.

        A bare NetBIOS name yields an empty string, which instructs the caller to fall back to
        the domain of the current host. No network activity is performed.

    .PARAMETER Identity
        The raw identity as supplied by the operator. Inspected for DC= components before any
        other derivation is attempted.

    .PARAMETER ServerName
        The already normalised server name produced by ConvertTo-PSADDomainControllerName.
        Used for the fully qualified name derivation when the identity is not a distinguished
        name.

    .EXAMPLE
        Get-PSADDomainHintFromIdentity -Identity 'CN=DC01,OU=Domain Controllers,DC=corp,DC=contoso,DC=com' -ServerName 'DC01'

        Returns 'corp.contoso.com' from the distinguished name components.

    .EXAMPLE
        Get-PSADDomainHintFromIdentity -Identity 'DC01.corp.contoso.com' -ServerName 'DC01.corp.contoso.com'

        Returns 'corp.contoso.com' by stripping the host label.

    .OUTPUTS
        System.String

    .NOTES
        Internal helper. Not exported.
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Identity,

        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ServerName
    )

    process
    {
        $domainComponent = @(
            ($Identity -split '(?<!\\),') |
                Where-Object -FilterScript { $_.Trim() -like 'DC=*' } |
                ForEach-Object -Process { (($_.Trim() -split '=', 2)[1] -replace '\\(.)', '$1').Trim() }
        )

        if ($domainComponent.Count -gt 0)
        {
            $hint = $domainComponent -join '.'
            Write-Verbose -Message ("Domain '{0}' derived from the distinguished name components." -f $hint)

            return $hint
        }

        if ($ServerName.Contains('.'))
        {
            $hint = $ServerName.Substring($ServerName.IndexOf('.') + 1)
            Write-Verbose -Message ("Domain '{0}' derived from the fully qualified server name." -f $hint)

            return $hint
        }

        Write-Verbose -Message 'No domain could be derived from the identity. The domain of the current host will be used.'

        return [System.String]::Empty
    }
}
