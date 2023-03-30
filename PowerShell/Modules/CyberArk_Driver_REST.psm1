<#
#>
Import-Module ".\Modules\PS_Script_Utilities.psm1" -Force
Import-Module ".\Modules\CustomWebRequest.psm1" -Force
#region CyberArk REST API Referenc
# Create a Hash Table to hold all of the Authentication Methods and Required Attributes.
$PVWAAUTHURL = @{
    CyberArk    = @{
        Path = "/API/auth/Cyberark/Logon"
        Body =  @{
            username = ""
            password = ""
            newPassword = ""
            concurrentSession = $true
        }
        Headers = @{}
    }
    Windows     = @{
        Path = "/API/auth/Windows/Logon"
        Body =  @{
            username = ""
            password = ""
            newPassword = ""
            concurrentSession = $true
        }
        Headers = @{}
    }
    LDAP        = @{
        Path = "/API/auth/LDAP/Logon"
        Body =  @{
            username = ""
            password = ""
            newPassword = ""
            concurrentSession = $true
        }
        Headers = @{}
    }
    SAML        = @{
        Path = "/API/auth/SAML/Logon"
        Body = @{
            SAMLResponse = ""
            apiUse = $true
            concurrentSession = $true
        }
        Headers = @{}
    }
    RADIUS      = @{
        Path = "/API/auth/RADIUS/Logon"
        Body =  @{
            username = ""
            password = ""
            newPassword = ""
            concurrentSession = $true
        }
        Headers = @{}
    }
    Shared      = @{
        Path = "/WebServices/auth/Shared/RestfulAuthenticationService.svc/Logon/"
        Body = @{}
        Headers = @{}
    }
    PKIPN       = @{
        Path = "/API/auth/PKIPN/Logon"
        Body = @{
            username = ""
            password = ""
            newPassword = ""
            concurrentSession = $true
            secureMode = $true
            type = "pkipn"
            additionalInfo = ""
        }
        Headers = @{}
    }
    Logoff      = @{
        Path = "/API/Auth/Logoff/"
        Body = @{}
        Headers = @{}
    }
    LogoffShared= @{
        Path = "/WebServices/auth/Shared/RestfulAuthenticationService.svc/Logoff/"
        Body = @{}
        Headers = @{}
    }
}

#endregion CyberArk REST API Referenc
#region CyberArk REST API Calls
#region Authentication
function Get-SessionToken
{
    <#
        .SYNOPSIS
        Returns the user authorization session token as a string.

        .DESCRIPTION
        This function will use the requested authentication type to retrieve a valid
        session token from the PVWA API endpoint.

        .PARAMETER BaseURI
        This is the Base URI for the PVWA server.  Should be like 'https://pvwa.company.com:443/PasswordVault'

        .PARAMETER AuthType
        This is the authentication method to be used.
        Valid values:  "CyberArk","Windows","LDAP","SAML","RADIUS","Shared","PKIPIN"

        .PARAMETER Credential
        Some authentication methods require a username and password to be provided.
    #>
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true
        )]
        [System.UriBuilder] $BaseURI,

        [parameter(
            Mandatory = $true
        )]
        [ValidateScript({
            if (-not ($PVWAAUTHURL.Keys -contains $PSItem))
            {return $false}
            else {return $true}
        })]
        [string] $AuthType,

        [parameter(
            Mandatory = $false
        )]
        [pscredential] $Credential,

        [parameter(
            Mandatory = $false
        )]
        [bool] $IgnoreSSL = $false
    )

    # Make a copy of the BaseURI so we don't change it.
    $_baseURI = [System.UriBuilder]::New($BaseURI.Uri)

    # Build the full URL from the BaseURI and the path from the requested authentication type.
    $_baseURI.Path = Join-Parts -Parent $_baseURI.Path -Child $PVWAAUTHURL[$AuthType]["Path"] -Separator "/"

    # Get the full URL from the Base URI.
    $_fullURL = $_baseURI.Uri

    # Get the required body attributes for the requested authentication type.
    $_authBody = $PVWAAUTHURL[$AuthType]["Body"]

    # Get the headers.
    $_authHeaders = $PVWAAUTHURL[$AuthType]["Headers"]

    # Call the proper function for the requested authentication type.
    switch ($AuthType)
    {
        "CyberArk"
        {
            $_sessionAttributes = @{
                FullURI = $_fullURL
                Credential = $Credential
                Body = $_authBody
                Headers = $_authHeaders
                IgnoreSSL = $IgnoreSSL
            }
            $sessionToken = Get-AuthSessionCyberArk @_sessionAttributes
        }

        "Windows"
        {
            $_sessionAttributes = @{
                FullURI = $_fullURL
                Credential = $Credential
                Body = $_authBody
                IgnoreSSL = $IgnoreSSL
            }
            $sessionToken = Get-AuthSessionWindows @_sessionAttributes
        }

        "LDAP"
        {
            $_sessionAttributes = @{
                FullURI = $_fullURL
                Credential = $Credential
                Body = $_authBody
                IgnoreSSL = $IgnoreSSL
            }
            $sessionToken = Get-AuthSessionLDAP @_sessionAttributes
        }

        "SAML"
        {
            $_sessionAttributes = @{
                FullURI = $_fullURL
                Credential = $Credential
                Body = $_authBody
                Headers = $_authHeaders
                IgnoreSSL = $IgnoreSSL
            }
            $sessionToken = Get-AuthSessionSAML @_sessionAttributes
        }

        "RADIUS"
        {
            $_sessionAttributes = @{
                FullURI = $_fullURL
                Credential = $Credential
                Body = $_authBody
                Headers = $_authHeaders
                IgnoreSSL = $IgnoreSSL
            }
            $sessionToken = Get-AuthSessionRADIUS @_sessionAttributes
        }

        "Shared"
        {
            $_sessionAttributes = @{
                FullURI = $_fullURL
                Credential = $Credential
                Body = $_authBody
                Headers = $_authHeaders
                IgnoreSSL = $IgnoreSSL
            }
            $sessionToken = Get-AuthSessionShared @_sessionAttributes
        }

        "PKIPN"
        {
            $_sessionAttributes = @{
                FullURI = $_fullURL
                Credential = $Credential
                Body = $_authBody
                IgnoreSSL = $IgnoreSSL
            }
            $sessionToken = Get-AuthSessionPKIPN @_sessionAttributes
        }
    }
    return $sessionToken
}
function Get-AuthSessionCyberArk
{
    <#
        .SYNOPSIS
        Returns the user authorization session token as a string.

        .DESCRIPTION
        This function will use CyberArk authentication type to retrieve a valid
        session token from the PVWA API endpoint.

        .PARAMETER FullURI
        This is the Base URI for the PVWA server.  Should be like 'https://pvwa.company.com:443/PasswordVault'

        .PARAMETER Credential
        This is the Username and Password stored in a PSCredential object.

        .PARAMETER Body
        This is a hashtable with the required body attributes.
    #>
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string] $FullURI,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [pscredential] $Credential,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [hashtable] $Body,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [hashtable] $Headers,

        [parameter(
            Mandatory = $false
        )]
        [bool] $IgnoreSSL = $false
    )

    # Set the success codes.
    $_successCodes = (200)

    # Update the Body attributes.
    $Body["username"] = $Credential.UserName
    $Body["password"] = $Credential.GetNetworkCredential().Password

    # Create the session parameters.
    $_requestParameters = @{
        URI = $FullURI
        Method = "Post"
        Body = $Body
        ContentType = "application/json"
        SessionVariable = 'requestSession'
        SkipCertificateCheck = $IgnoreSSL
    }
    # Make the request
    $result = Invoke-CustomWebRequest @_requestParameters

    # Check the result.
    if (Test-IsSuccess -StatusCode $result["StatusCode"] -SuccessCodes $_successCodes)
    {
        # Request was successful.
        #  Pull the session token from the body.
        $_body = $result["Body"]

        #  Make sure the body isn't blank or null.
        if ($_body)
        {
            # Pull the Content from the Body.
            $_bodyContent = $_body.Content

            # Strip the quotes and assign to the token.
            $_sessionToken = $_bodyContent.Trim('"')
        }
        else
        {
            $_sessionToken = $null
        }

        # Return the token
        return $_sessionToken
    }
    else
    {
        # Request failed.
        return $null
    }

}
function Get-AuthSessionWindows
{
    <#
        .SYNOPSIS
        Returns the user authorization session token as a string.

        .DESCRIPTION
        This function will use CyberArk authentication type to retrieve a valid
        session token from the PVWA API endpoint.

        .PARAMETER FullURI
        This is the Base URI for the PVWA server.  Should be like 'https://pvwa.company.com:443/PasswordVault'

        .PARAMETER Credential
        This is the Username and Password stored in a PSCredential object.

        .PARAMETER Body
        This is a hashtable with the required body attributes.
    #>
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string] $FullURI,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [pscredential] $Credential,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [hashtable] $Body,

        [parameter(
            Mandatory = $false
        )]
        [bool] $IgnoreSSL = $false
    )
}
function Get-AuthSessionLDAP
{
    <#
        .SYNOPSIS
        Returns the user authorization session token as a string.

        .DESCRIPTION
        This function will use CyberArk authentication type to retrieve a valid
        session token from the PVWA API endpoint.

        .PARAMETER FullURI
        This is the Base URI for the PVWA server.  Should be like 'https://pvwa.company.com:443/PasswordVault'

        .PARAMETER Credential
        This is the Username and Password stored in a PSCredential object.

        .PARAMETER Body
        This is a hashtable with the required body attributes.
    #>
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string] $FullURI,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [pscredential] $Credential,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [hashtable] $Body,

        [parameter(
            Mandatory = $false
        )]
        [bool] $IgnoreSSL = $false
    )

    # Set the success codes.
    $_successCodes = (200)

    # Update the Body attributes.
    $Body["username"] = $Credential.UserName
    $Body["password"] = $Credential.GetNetworkCredential().Password

    # Create the session parameters.
    $_requestParameters = @{
        URI = $FullURI
        Method = "Post"
        Body = $Body
        ContentType = "application/json"
        SessionVariable = 'requestSession'
        SkipCertificateCheck = $IgnoreSSL
    }
    # Make the request
    $result = Invoke-CustomWebRequest @_requestParameters

    # Check the result.
    if (Test-IsSuccess -StatusCode $result["StatusCode"] -SuccessCodes $_successCodes)
    {
        # Request was successful.
        #  Pull the session token from the body.
        $_body = $result["Body"]

        #  Make sure the body isn't blank or null.
        if ($_body)
        {
            # Pull the Content from the Body.
            $_bodyContent = $_body.Content

            # Strip the quotes and assign to the token.
            $_sessionToken = $_bodyContent.Trim('"')
        }
        else
        {
            $_sessionToken = $null
        }

        # Return the token
        return $_sessionToken
    }
    else
    {
        # Request failed.
        return $null
    }
}
function Get-AuthSessionSAML
{
    <#
        .SYNOPSIS
        Returns the user authorization session token as a string.

        .DESCRIPTION
        This function will use CyberArk authentication type to retrieve a valid
        session token from the PVWA API endpoint.

        .PARAMETER FullURI
        This is the Base URI for the PVWA server.  Should be like 'https://pvwa.company.com:443/PasswordVault'

        .PARAMETER Body
        This is a hashtable with the required body attributes.
    #>
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string] $FullURI,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [hashtable] $Body,

        [parameter(
            Mandatory = $false
        )]
        [bool] $IgnoreSSL = $false
    )

    # Get IDP URL

    # Get SAML token

    # Get Authentication Token
}
function Get-AuthSessionRADIUS
{
    <#
        .SYNOPSIS
        Returns the user authorization session token as a string.

        .DESCRIPTION
        This function will use CyberArk authentication type to retrieve a valid
        session token from the PVWA API endpoint.

        .PARAMETER FullURI
        This is the Base URI for the PVWA server.  Should be like 'https://pvwa.company.com:443/PasswordVault'

        .PARAMETER Credential
        This is the Username and Password stored in a PSCredential object.

        .PARAMETER Body
        This is a hashtable with the required body attributes.
    #>
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string] $FullURI,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [pscredential] $Credential,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [hashtable] $Body,

        [parameter(
            Mandatory = $false
        )]
        [bool] $IgnoreSSL = $false
    )
    # Set the success codes.
    $_successCodes = (200)

    # Update the Body attributes.
    $Body["username"] = $Credential.UserName
    $Body["password"] = $Credential.GetNetworkCredential().Password

    # Create the session parameters.
    $_requestParameters = @{
        URI = $FullURI
        Method = "Post"
        Body = $Body
        ContentType = "application/json"
        SessionVariable = 'requestSession'
        SkipCertificateCheck = $IgnoreSSL
    }
    # Make the request
    $result = Invoke-CustomWebRequest @_requestParameters

    # Check the result.
    if (Test-IsSuccess -StatusCode $result["StatusCode"] -SuccessCodes $_successCodes)
    {
        # Request was successful.
        #  Pull the session token from the body.
        $_body = $result["Body"]

        #  Make sure the body isn't blank or null.
        if ($_body)
        {
            # Pull the Content from the Body.
            $_bodyContent = $_body.Content

            # Strip the quotes and assign to the token.
            $_sessionToken = $_bodyContent.Trim('"')
        }
        else
        {
            $_sessionToken = $null
        }

        # Return the token
        return $_sessionToken
    }
    else
    {
        # Request failed.
        return $null
    }
}
function Get-AuthSessionShared
{
    <#
        .SYNOPSIS
        Returns the user authorization session token as a string.

        .DESCRIPTION
        This function will use CyberArk authentication type to retrieve a valid
        session token from the PVWA API endpoint.

        .PARAMETER FullURI
        This is the Base URI for the PVWA server.  Should be like 'https://pvwa.company.com:443/PasswordVault'

        .PARAMETER Credential
        This is the Username and Password stored in a PSCredential object.
    #>
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string] $FullURI,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [pscredential] $Credential,

        [parameter(
            Mandatory = $false
        )]
        [bool] $IgnoreSSL = $false
    )
}
function Get-AuthSessionPKIPN
{
    <#
        .SYNOPSIS
        Returns the user authorization session token as a string.

        .DESCRIPTION
        This function will use CyberArk authentication type to retrieve a valid
        session token from the PVWA API endpoint.

        .PARAMETER FullURI
        This is the Base URI for the PVWA server.  Should be like 'https://pvwa.company.com:443/PasswordVault'

        .PARAMETER Body
        This is a hashtable with the required body attributes.
    #>
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string] $FullURI,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [pscredential] $Credential,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [hashtable] $Body,

        [parameter(
            Mandatory = $false
        )]
        [bool] $IgnoreSSL = $false
    )

    # Get the username from the credential
    $username = $Credential.UserName

    # Decode the credential.
    if ($username -eq "X509Certificate2")
    {
        # Credential is created from a serialized certificate.
        $stringSerializedCertificate = $Credential.GetNetworkCredential().Password

        # Convert the new string to a byte array.
        $newExportedCertificate = [System.Text.Encoding]::Unicode.GetBytes($stringSerializedCertificate)

        # Import the serialized certificate to an X509 certificate from the PS Credential
        $selectedClientCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::New($newExportedCertificate)
    }
    else
    {
        # Get the certificate from the PS Credential object.
        $selectedClientCertificate = Get-CertificateFromPSCredential -Credential $Credential
    }

    # Set the success codes.
    $_successCodes = (200)

    # Create the session parameters.
    $_requestParameters = @{
        URI = $FullURI
        Method = "Post"
        Body = $Body
        #ContentType = "application/json"
        Headers = @{
            ContentType = "application/json"
        }
        SessionVariable = 'requestSession'
        Certificate = $selectedClientCertificate
        SkipCertificateCheck = $IgnoreSSL
    }
    # Make the request
    $result = Invoke-CustomWebRequest @_requestParameters
    #$result = Invoke-TheCustomWebRequest -RawProperties $_requestParameters

    # Check the result.
    if (Test-IsSuccess -StatusCode $result["StatusCode"] -SuccessCodes $_successCodes)
    {
        # Request was successful.
        #  Pull the session token from the body.
        $_body = $result["Body"]

        #  Make sure the body isn't blank or null.
        if ($_body)
        {
            # Pull the Content from the Body.
            $_bodyContent = $_body.Content

            # Strip the quotes and assign to the token.
            $_sessionToken = $_bodyContent.Trim('"')
        }
        else
        {
            $_sessionToken = $null
        }

        # Return the token
        return $_sessionToken
    }
    else
    {
        # Request failed.
        return $null
    }
}
function Clear-SessionToken
{
    <#
        .SYNOPSIS
        Returns the user authorization session token as a string.

        .DESCRIPTION
        This function will use the requested authentication type to retrieve a valid
        session token from the PVWA API endpoint.

        .PARAMETER BaseURI
        This is the Base URI for the PVWA server.  Should be like 'https://pvwa.company.com:443/PasswordVault'

        .PARAMETER SessionToken
        This is the Session Token from the Get-SessionToken.

    #>
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [System.UriBuilder] $BaseURI,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [ValidateScript({
            if (-not ($PVWAAUTHURL.Keys -contains $PSItem))
            {return $false}
            else {return $true}
        })]
        [string] $AuthType,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string] $SessionToken,

        [parameter(
            Mandatory = $false
        )]
        [bool] $IgnoreSSL = $false

    )

    # Override the Authentication Type.
    if ($AuthType -ieq "Shared")
    {
        $_authType = "LogoffShared"
    }
    else
    {
        $_authType = "Logoff"
    }

    # Make a copy of the BaseURI so we don't change it.
    $_baseURI = [System.UriBuilder]::New($BaseURI.Uri)

    # Build the full URL from the BaseURI and the path from the requested authentication type.
    $_baseURI.Path = Join-Parts -Parent $_baseURI.Path -Child $PVWAAUTHURL[$_authType]["Path"] -Separator "/"

    # Get the full URL from the Base URI.
    $_fullURL = $_baseURI.Uri

    # Create the headers.
    $_headers = @{
        Authorization = $SessionToken
    }

    # Set the success codes.
    $_successCodes = (200)

    # Create the session parameters.
    $_requestParameters = @{
        Headers = $_headers
        URI = $_fullURL
        Method = "Post"
        ContentType = "application/json"
        SkipCertificateCheck = $IgnoreSSL
    }
    # Make the request
    $result = Invoke-CustomWebRequest @_requestParameters

    # Check the result.
    if (Test-IsSuccess -StatusCode $result["StatusCode"] -SuccessCodes $_successCodes)
    {
        # Request was successful.
        return $result["Body"]
    }
    else
    {
        # Request failed.
        return $null
    }
}
#endregion Authentication
#region Server
function Get-VaultName
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [System.UriBuilder] $BaseURI,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string] $SessionToken,

        [parameter(
            Mandatory = $false
        )]
        [bool] $IgnoreSSL = $false
    )
    #https://<IIS_Server_Ip>/PasswordVault/WebServices/PIMServices.svc/Server
    $_stubPath = "WebServices/PIMServices.svc/Server"

    # Make a copy of the BaseURI so we don't change it.
    $_baseURI = [System.UriBuilder]::New($BaseURI.Uri)

    # Build the full URL from the BaseURI and the path from the requested authentication type.
    $_baseURI.Path = Join-Parts -Parent $_baseURI.Path -Child $_stubPath -Separator "/"

    # Get the full URL from the Base URI.
    $_fullURL = $_baseURI.Uri

    # Create the headers.
    $_headers = @{
        Authorization = $SessionToken
    }

    # Set the success codes.
    $_successCodes = (200)

    # Create the session parameters.
    $_requestParameters = @{
        URI = $_fullURL
        Method = "Get"
        ContentType = "application/json"
        Headers = $_headers
        SkipCertificateCheck = $IgnoreSSL
    }
    # Make the request
    $result = Invoke-CustomWebRequest @_requestParameters

    # Check the result.
    if (Test-IsSuccess -StatusCode $result["StatusCode"] -SuccessCodes $_successCodes)
    {
        # Request was successful.
        #  Pull the session token from the body.
        $_body = $result["Body"]

        #  Make sure the body isn't blank or null.
        if ($_body)
        {
            # Pull the Content from the Body.
            $_bodyContent = $_body.Content

            # Strip the quotes and assign to the token.
            $_Content = $_bodyContent.Trim('"')
        }
        else
        {
            $_Content = $null
        }

        # Return the token
        return $_Content
    }
    else
    {
        # Request failed.
        return $null
    }
}
function Get-VaultInfo
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [System.UriBuilder] $BaseURI,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string] $SessionToken,

        [parameter(
            Mandatory = $false
        )]
        [bool] $IgnoreSSL = $false
    )
    #https://<IIS_Server_Ip>/PasswordVault/WebServices/PIMServices.svc/Verify
    $_stubPath = "WebServices/PIMServices.svc/Verify"

    # Make a copy of the BaseURI so we don't change it.
    $_baseURI = [System.UriBuilder]::New($BaseURI.Uri)

    # Build the full URL from the BaseURI and the path from the requested authentication type.
    $_baseURI.Path = Join-Parts -Parent $_baseURI.Path -Child $_stubPath -Separator "/"

    # Get the full URL from the Base URI.
    $_fullURL = $_baseURI.Uri

    # Create the headers.
    $_headers = @{
        Authorization = $SessionToken
    }

    # Set the success codes.
    $_successCodes = (200)

    # Create the session parameters.
    $_requestParameters = @{
        URI = $_fullURL
        Method = "Get"
        ContentType = "application/json"
        Headers = $_headers
        SkipCertificateCheck = $IgnoreSSL
    }
    # Make the request
    $result = Invoke-CustomWebRequest @_requestParameters

    # Check the result.
    if (Test-IsSuccess -StatusCode $result["StatusCode"] -SuccessCodes $_successCodes)
    {
        # Request was successful.
        #  Pull the session token from the body.
        $_body = $result["Body"]

        #  Make sure the body isn't blank or null.
        if ($_body)
        {
            # Pull the Content from the Body.
            $_bodyContent = $_body.Content

            # Strip the quotes and assign to the token.
            $_Content = $_bodyContent.Trim('"')
        }
        else
        {
            $_Content = $null
        }

        # Return the token
        return $_Content
    }
    else
    {
        # Request failed.
        return $null
    }
}
#endregion Server
#region System Health
function Get-HealthSummary
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [System.UriBuilder] $BaseURI,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string] $SessionToken,

        [parameter(
            Mandatory = $false
        )]
        [bool] $IgnoreSSL = $false
    )
    #https://<IIS_Server_Ip>/PasswordVault/api/ComponentsMonitoringSummary
    $_stubPath = "api/ComponentsMonitoringSummary"

    # Make a copy of the BaseURI so we don't change it.
    $_baseURI = [System.UriBuilder]::New($BaseURI.Uri)

    # Build the full URL from the BaseURI and the path from the requested authentication type.
    $_baseURI.Path = Join-Parts -Parent $_baseURI.Path -Child $_stubPath -Separator "/"

    # Get the full URL from the Base URI.
    $_fullURL = $_baseURI.Uri

    # Create the headers.
    $_headers = @{
        Authorization = $SessionToken
    }

    # Set the success codes.
    $_successCodes = (200)

    # Create the session parameters.
    $_requestParameters = @{
        URI = $_fullURL
        Method = "Get"
        ContentType = "application/json"
        Headers = $_headers
        SkipCertificateCheck = $IgnoreSSL
    }
    # Make the request
    $result = Invoke-CustomWebRequest @_requestParameters

    # Check the result.
    if (Test-IsSuccess -StatusCode $result["StatusCode"] -SuccessCodes $_successCodes)
    {
        # Request was successful.
        #  Pull the session token from the body.
        $_body = $result["Body"]

        #  Make sure the body isn't blank or null.
        if ($_body)
        {
            # Pull the Content from the Body.
            $_bodyContent = $_body.Content

            # Strip the quotes and assign to the token.
            $_Content = $_bodyContent.Trim('"')
        }
        else
        {
            $_Content = $null
        }

        # Return the token
        return $_Content
    }
    else
    {
        # Request failed.
        return $null
    }
}
#endregion System Health
#endregion CyberArk REST API Calls
