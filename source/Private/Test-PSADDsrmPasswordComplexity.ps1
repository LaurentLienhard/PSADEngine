function Test-PSADDsrmPasswordComplexity
{
    <#
    .SYNOPSIS
        Validates a DSRM password held in a SecureString against Tier 0 complexity rules.

    .DESCRIPTION
        Inspects a SecureString without ever materialising the secret as a managed
        System.String. The characters are read one at a time from the unmanaged BSTR buffer
        and classified, after which the buffer is zeroed and freed in a finally block. This
        avoids leaving a recoverable copy of the DSRM password on the managed heap where it
        would survive until an indeterminate garbage collection.

        The function enforces:
          - A configurable minimum length (14 characters by default, exceeding the Microsoft
            Tier 0 baseline of 12).
          - A configurable number of distinct character categories (upper, lower, digit,
            non-alphanumeric); three of four by default.
          - The absence of control characters. This is a hard failure because carriage
            return, line feed or NUL inside the secret would corrupt the ntdsutil standard
            input script and could be used to inject additional ntdsutil directives.

        The function never emits the password, nor any fragment of it, on any stream.

    .PARAMETER Password
        The candidate DSRM password as a SecureString. The instance is inspected in place
        and is neither copied nor disposed by this function.

    .PARAMETER MinimumLength
        The minimum number of characters the password must contain. Defaults to 14 which is
        the recommended Tier 0 break-glass credential length.

    .PARAMETER MinimumCategory
        The minimum number of distinct character categories that must be present out of
        upper case, lower case, digit and non-alphanumeric. Defaults to 3.

    .EXAMPLE
        $secret = Read-Host -AsSecureString -Prompt 'DSRM password'
        Test-PSADDsrmPasswordComplexity -Password $secret

        Returns an object whose IsValid property indicates policy compliance.

    .EXAMPLE
        $result = Test-PSADDsrmPasswordComplexity -Password $secret -MinimumLength 20 -MinimumCategory 4
        if (-not $result.IsValid) { $result.FailureReason }

        Applies a stricter policy and lists every rule that was violated.

    .OUTPUTS
        System.Management.Automation.PSCustomObject

    .NOTES
        Internal helper. Not exported.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param
    (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [System.Security.SecureString]
        $Password,

        [Parameter()]
        [ValidateRange(1, 256)]
        [System.Int32]
        $MinimumLength = 14,

        [Parameter()]
        [ValidateRange(1, 4)]
        [System.Int32]
        $MinimumCategory = 3
    )

    begin
    {
        $bytesPerChar = 2
        $lowWordMask = 0xFFFF
    }

    process
    {
        $failureReason = [System.Collections.Generic.List[System.String]]::new()

        $hasUpper = $false
        $hasLower = $false
        $hasDigit = $false
        $hasSymbol = $false
        $hasControl = $false

        $length = $Password.Length
        $unmanagedBuffer = [System.IntPtr]::Zero

        try
        {
            $unmanagedBuffer = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)

            for ($index = 0; $index -lt $length; $index++)
            {
                # ReadInt16 is signed; mask back to the unsigned UTF-16 code unit.
                $codeUnit = [System.Int32][System.Runtime.InteropServices.Marshal]::ReadInt16($unmanagedBuffer, $index * $bytesPerChar)
                $character = [System.Char]($codeUnit -band $lowWordMask)

                if ([System.Char]::IsControl($character))
                {
                    $hasControl = $true
                }
                elseif ([System.Char]::IsUpper($character))
                {
                    $hasUpper = $true
                }
                elseif ([System.Char]::IsLower($character))
                {
                    $hasLower = $true
                }
                elseif ([System.Char]::IsDigit($character))
                {
                    $hasDigit = $true
                }
                else
                {
                    $hasSymbol = $true
                }
            }
        }
        finally
        {
            if ($unmanagedBuffer -ne [System.IntPtr]::Zero)
            {
                # Deterministic scrub of the decrypted secret.
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($unmanagedBuffer)
            }
        }

        $categoryCount = @($hasUpper, $hasLower, $hasDigit, $hasSymbol).Where({ $_ }).Count

        if ($length -lt $MinimumLength)
        {
            $failureReason.Add(('The password is {0} characters long but the policy requires at least {1}.' -f $length, $MinimumLength))
        }

        if ($categoryCount -lt $MinimumCategory)
        {
            $failureReason.Add(('The password uses {0} character categories but the policy requires at least {1} of upper case, lower case, digit and non-alphanumeric.' -f $categoryCount, $MinimumCategory))
        }

        if ($hasControl)
        {
            $failureReason.Add('The password contains a control character. Control characters are rejected because they would corrupt the ntdsutil input script.')
        }

        <#
            The narration reports the verdict and the aggregate measurements only. The
            per category booleans are deliberately not narrated: they describe the shape of
            a live Tier 0 secret and would narrow a brute force search space if a transcript
            were ever captured. No character, fragment or length-preserving echo of the
            password reaches any stream.
        #>
        if (0 -eq $failureReason.Count)
        {
            Write-Verbose -Message ('Password complexity validation PASSED: {0} characters, {1} of 4 character categories, no control character.' -f $length, $categoryCount)
        }
        else
        {
            Write-Verbose -Message ('Password complexity validation FAILED against {0} policy rule(s). Read the FailureReason property for the detail.' -f $failureReason.Count)
        }

        [PSCustomObject]@{
            IsValid            = ($failureReason.Count -eq 0)
            Length             = $length
            CategoryCount      = $categoryCount
            HasUpperCase       = $hasUpper
            HasLowerCase       = $hasLower
            HasDigit           = $hasDigit
            HasNonAlphanumeric = $hasSymbol
            HasControlChar     = $hasControl
            FailureReason      = $failureReason.ToArray()
        }
    }
}
