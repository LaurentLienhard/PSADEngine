function Format-PSADLdapFilterValue
{
    <#
    .SYNOPSIS
        Escapes a value for safe inclusion in an LDAP search filter.

    .DESCRIPTION
        Applies the RFC 4515 assertion value escaping rules so that attacker influenced or
        merely unusual input cannot alter the semantics of an LDAP search filter. Without
        this escaping, a value such as '*' turns an equality match into a presence match and
        a value containing parentheses can close the current filter component and append a
        new one, which is the LDAP equivalent of SQL injection.

        The backslash is escaped first, otherwise the escape sequences generated for the
        remaining metacharacters would themselves be re-escaped and corrupted.

        Escaped characters: backslash, asterisk, opening parenthesis, closing parenthesis
        and the NUL character.

    .PARAMETER Value
        The raw assertion value to escape, for example a sAMAccountName or a user principal
        name supplied by an operator. An empty string is returned unchanged.

    .EXAMPLE
        Format-PSADLdapFilterValue -Value 'jdoe'

        Returns 'jdoe' because the value contains no metacharacter.

    .EXAMPLE
        Format-PSADLdapFilterValue -Value 'svc_app01)(objectClass=*'

        Returns the fully escaped value so the injected filter component is neutralised.

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
        [AllowEmptyString()]
        [System.String]
        $Value
    )

    process
    {
        if ([System.String]::IsNullOrEmpty($Value))
        {
            return [System.String]::Empty
        }

        $escaped = $Value

        # The backslash must be escaped before any sequence that introduces one.
        $escaped = $escaped -replace '\\', '\5c'
        $escaped = $escaped -replace '\*', '\2a'
        $escaped = $escaped -replace '\(', '\28'
        $escaped = $escaped -replace '\)', '\29'
        $escaped = $escaped -replace "`0", '\00'

        return $escaped
    }
}
