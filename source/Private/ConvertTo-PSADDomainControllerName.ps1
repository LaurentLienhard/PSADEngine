function ConvertTo-PSADDomainControllerName
{
    <#
    .SYNOPSIS
        Normalises a domain controller identity into a safe, single-label or FQDN server name.

    .DESCRIPTION
        Accepts the many shapes an operator may use to designate a domain controller and
        returns a single canonical server name that is safe to embed inside an ntdsutil
        command line. The function deliberately performs no network activity so that it can
        be unit tested in isolation and so that input sanitisation happens before any Tier 0
        operation is attempted.

        Supported input shapes:
          - Distinguished name: 'CN=DC01,OU=Domain Controllers,DC=corp,DC=contoso,DC=com'
          - NTDS settings DN  : 'CN=NTDS Settings,CN=DC01,CN=Servers,...'
          - NetBIOS name      : 'DC01'
          - Computer account  : 'DC01$'
          - Fully qualified   : 'DC01.corp.contoso.com'

        SECURITY: the returned value is validated against a strict allow-list character set
        (letters, digits, dot, dash, underscore). This is the primary control preventing
        command injection into the ntdsutil standard input script, because the server name
        is written verbatim as part of the 'reset password on server <name>' directive.

    .PARAMETER Identity
        The raw domain controller identity supplied by the caller. Accepts a distinguished
        name, an NTDS Settings distinguished name, a NetBIOS name, a computer account name
        ending with a dollar sign, or a fully qualified domain name.

    .EXAMPLE
        ConvertTo-PSADDomainControllerName -Identity 'CN=DC01,OU=Domain Controllers,DC=corp,DC=contoso,DC=com'

        Returns 'DC01'.

    .EXAMPLE
        'DC01$' | ConvertTo-PSADDomainControllerName

        Returns 'DC01' after stripping the computer account suffix.

    .OUTPUTS
        System.String

    .NOTES
        Internal helper. Not exported.
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Identity
    )

    begin
    {
        # Allow-list for a DNS label / FQDN. Anything else is rejected outright.
        $safeNamePattern = '^[A-Za-z0-9][A-Za-z0-9._-]{0,253}[A-Za-z0-9]$'
        $maximumNameLength = 255
    }

    process
    {
        $candidate = $Identity.Trim()

        if ([System.String]::IsNullOrWhiteSpace($candidate))
        {
            throw [System.ArgumentException]::new(
                'The domain controller identity cannot be blank or whitespace only.',
                'Identity')
        }

        if ($candidate -like 'CN=*')
        {
            # Split on the first unescaped comma to isolate the left most RDN.
            $relativeDistinguishedName = ($candidate -split '(?<!\\),', 2)[0]
            $candidate = ($relativeDistinguishedName -split '=', 2)[1]

            # Un-escape DN special characters (for example 'CN=DC\,01').
            $candidate = $candidate -replace '\\(.)', '$1'
            $candidate = $candidate.Trim()

            <#
                An NTDS Settings DN points at the settings object, not the server object.
                In that case the server name lives in the *second* RDN.
            #>
            if ($candidate -eq 'NTDS Settings')
            {
                $remainder = ($Identity.Trim() -split '(?<!\\),', 3)
                if ($remainder.Count -lt 2)
                {
                    throw [System.ArgumentException]::new(
                        ("Unable to derive a server name from the NTDS Settings distinguished name '{0}'." -f $Identity),
                        'Identity')
                }

                $candidate = (($remainder[1] -split '=', 2)[1] -replace '\\(.)', '$1').Trim()
            }
        }

        # Strip a trailing computer account marker, for example 'DC01$'.
        $candidate = $candidate.TrimEnd('$')

        if ($candidate.Length -gt $maximumNameLength)
        {
            throw [System.ArgumentException]::new(
                ("The resolved domain controller name exceeds {0} characters and cannot be a valid host name." -f $maximumNameLength),
                'Identity')
        }

        if ($candidate -notmatch $safeNamePattern)
        {
            throw [System.ArgumentException]::new(
                ("The resolved domain controller name '{0}' contains characters that are not permitted in a host name. " -f $candidate) +
                'Only letters, digits, dot, dash and underscore are accepted. This restriction prevents command injection into ntdsutil.',
                'Identity')
        }

        Write-Verbose -Message ("Identity '{0}' normalised to server name '{1}'." -f $Identity, $candidate)

        $candidate
    }
}
