<#
#>
#region General Help Functions
function Get-BoolFromString
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string] $Text
    )
    switch -regex ($Text.Trim())
    {
        "^(1|true|yes|on|enabled)$" { $true }

        default { $false }
    }
}
function Join-Parts
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string] $Parent,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string] $Child,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string] $Separator = "/"
    )

    # Write-Host ("{0} : Parent:  {1}" -f $(Get-Date -Format "yyyy-MM-dd"), $Parent)
    # Write-Host ("{0} : Child :  {1}" -f $(Get-Date -Format "yyyy-MM-dd"), $Child)
    # Get the individual parts of the parent.
    [array]$_arrayPartsParent = $Parent.Split($Separator)

    # Get the individual parts of the child.
    [array]$_arrayPartsChild = $Child.Split($Separator)

    # Join the arrays.
    [array]$_joinedArray = $_arrayPartsParent + $_arrayPartsChild

    # Clean any blank/empty entries.
    [array]$_cleanedArray = $_joinedArray | Where-Object {$_}

    # Join the array into a string using the provided separator.
    $_returnString = $_cleanedArray -Join $Separator

    # Return the joind parts as a string.
    return $_returnString
}
function Get-MaskedBody
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [hashtable] $Body
    )

    # Convert to JSON and Convert from JSON to get a deep copy.
    $jsonBody = ConvertTo-Json -InputObject $Body
    $newBody = ConvertFrom-Json -InputObject $jsonBody

    # Check if the provided Hash Table has a Password field.
    if (($newBody.Password) -or ($newBody.password))
    {
        # Check if the password is blank.
        if ($newBody.password -ne "")
        {
            # Replace the password with Stars *
            $newBody.password = "**********"
        }

    }
    # Check if the provided Hash Table has a Password field.
    if (($newBody.NewPassword) -or ($newBody.newpassword))
    {
        # Check if the password is blank.
        if ($newBody.newpassword -ne "")
        {
            # Replace the password with Stars *
            $newBody.newpassword = "**********"
        }

    }

    return $newBody
}
function Get-SanitizedURL
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string] $Input
    )
}
function Test-IsSuccess
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [int] $StatusCode,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string[]] $SuccessCodes
    )
    # Test to see if the Status Code is in the list of SuccessCodes.
    if ($StatusCode -in $SuccessCodes)
    {
        return $true
    }
    else
    {
        return $false
    }
}
function Test-SessionToken
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [AllowEmptyString()]
        [string] $Token
    )
    # Test the token.
    if (($Token) -and ($Token -ne "") -and ($Token.Length -gt 200))
    {
        # Validation passed.  Return True.
        return $true
    }
    return $false
}
function Copy-HashTable
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [hashtable] $InputObject
    )
    # Convert to JSON and back to get a deep copy.
    $_toJSON = ConvertTo-Json -InputObject $InputObject

    # Convert from JSON back to a hash table.
    return ConvertFrom-Json -InputObject $_toJSON
}
function Get-CertificateAttributes
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [X509Certificate] $InputObject
    )
    # Create a return Hash Table.
    $_retHT = @{}

    # Get the wanted attributes to be displayed.
    $_retHT["FriendlyName"] = $InputObject.FriendlyName
    $_retHT["Thumbprint"]   = $InputObject.Thumbprint
    $_retHT["NotAfter"]     = ($InputObject.NotAfter | Out-String)
    $_retHT["NotBefore"]    = ($InputObject.NotBefore | Out-String)
    $_retHT["HasPrivateKey"] = $InputObject.HasPrivateKey
    $_retHT["SerialNumber"] = $InputObject.SerialNumber
    $_retHT["IssuerName"]   = $InputObject.IssuerName.Name

    # Create a table to hold all key usages.
    $_retKeyUsages = @{}

    # Get all Key Usages.
    $_keyUsages = $InputObject.Extensions

    # Loop over all Key Usages and add to the return Key Usages.
    foreach ($usage in $_keyUsages)
    {
        # Check the object type.  We want X509KeyUsageExtension and X509EnhancedKeyUsageExtension
        if ($usage.GetType() -eq [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension])
        {
            # Add the usage to the output object if the name is not null.
            if ($null -ne $usage.Oid.FriendlyName)
            {
                # Adding value to the Key Usages hash table.
                $_retKeyUsages[$usage.Oid.FriendlyName] = $usage.Oid.Value
            }

        }
        elseif ($usage.GetType() -eq [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension])
        {
            # Get the enhanced key usage list.
            $_enhancedKeyUsageList = $usage.EnhancedKeyUsages

            # Loop over the Enhanced Key Usage List
            foreach ($ekule in $_enhancedKeyUsageList)
            {
                # Add the usage to the output object if the name is not null.
                if ($null -ne $ekule.FriendlyName)
                {
                    # Adding value to the Key Usages hash table.
                    $_retKeyUsages[$ekule.FriendlyName] = $ekule.Value
                }
            }
        }
    }

    # If Key Usages have been found add them to the return object.
    if (($_retKeyUsages) -and ($_retKeyUsages.Count))
    {
        $_retHT["KeyUsage"] = $_retKeyUsages
    }

    return $_retHT
}
#endregion General Help Functions


