<#
    .SYNOPSIS
    Retrieves the specified account(s) from CyberArk and stores the password in 1 Password.

    .DESCRIPTION
    This script allows the user to Check-Out / Retrieve the password for the specified account(s) from CyberArk
    and stores the password into 1 Password.

    The script does require the use of an external EXE for retrieval of the SAML response.
    The EXE can be downloaded from here:  https://github.com/allynl93/getSAMLResponse-Interactive/releases/tag/Pre-built-Binary

    The script does require that the 1 Password CLI is installed and enabled.
    https://developer.1password.com/docs/cli/get-started/

    .PARAMETER PVWAURL
    [string]: This is the base URL of the PVWA web server.

    .INPUTS 
    [string] CyberArk Password Vault Web Access URL
    
    .OUTPUTS
    None

    .NOTES
    This script leverages the work of the following people.
        https://github.com/allynl93
        https://github.com/infamousjoeg
        https://github.com/pspete

    .LINK
    https://github.com/allynl93/getSAMLResponse-Interactive

    .LINK
    https://github.com/allynl93/getSAMLResponse-Interactive/releases

    .LINK
    https://developer.1password.com/docs/cli/get-started/
#>
[CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $PVWAURL = "https://epv.company.com",

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
            [ValidateSet('PEM','PPK','OpenSSH')]
        [int] $RequestTimeout = 30
    )

# These are the accounts to pull from CyberArk and store in 1 Password.
$Accounts = @{
    1 = @{
        Source = "epv://CyberArk_Safe_Name/CyberArk_Object_Name"
        Target = "op://1Password_Vault/1Password_Account_Name/password"
    }
    2 = @{
        Source = "epv://CyberArk_Safe_Name/CyberArk_Object_Name"
        Target = "op://1Password_Vault/1Password_Account_Name/password"
    }
}
#region Get IDP
### Get the IDP URL from the PVWA ###
# Build the Headers and Body
$idpHeaders = @{
    'Accept' = 'application/json'
}

$idpBody = @{
    'SAMLResponse' = '';
    'apiUse' = $true;
    'concurrentSession' = $false
}

$logonURL = $PVWAURL + "/PasswordVault/API/auth/saml/logon"
# The url is case sensitive after API.

# Build the web request options.
$idpWebRequestOptions = @{
    UseBasicParsing = $null
    Uri = $logonURL
    TimeoutSec = $RequestTimeout
    ContentType = "application/x-www-form-urlencoded"
    Method = "POST"
    Headers = $idpHeaders
    Body = $idpBody
    SessionVariable = 'idpSession' # This will be needed for the Token request.
}
# Use a try catch block to make the request.
try
{
    Write-Host ("Getting IDP URL from:  {0}" -f $logonURL)
    $idpResult = Invoke-WebRequest @idpWebRequestOptions
    Write-Verbose ("IDP URL:  {0}" -f $idpResult)
}
catch
{
    Write-Warning ("Failed to get IDP URL from:  {0}" -f $logonURL)
    Write-Warning ("IDP Result:  {0}" -f $idpResult)
    Write-Warning $_
    Exit $LASTEXITCODE
}
### End Section ###
#endRegion

#region Get SAML
### Get SAML Response ###

Write-Host ("Getting SAML Response.")
try
{
    # Using the pre-compiled code written by allynl93.  https://github.com/allynl93
    $samlResponse = .\getSAMLResponse\getSAMLResponse.exe $idpResult
    Write-Verbose ("SAML Response:  {0}" -f $samlResponse)
}
catch
{
    Write-Warning "Failed to get SAML response."
    Write-Warning $_
}
### End Section ###
#endRegion

#region Get CyberArk Auth Token
### Get CyberArk Auth Token ###
# Build the Headers and Body
$atHeaders = @{
    'Accept' = 'application/json'
}

$atBody = @{
    'SAMLResponse' = $samlResponse;
    'apiUse' = $true;
    'concurrentSession' = $true
}

$authURL = $PVWAURL + "/PasswordVault/API/Auth/SAML/Logon"

# Build the web request options.
$atWebRequestOptions = @{
    UseBasicParsing = $null
    Uri = $authURL
    TimeoutSec = $RequestTimeout
    ContentType = "application/x-www-form-urlencoded"
    Method = "POST"
    Headers = $atHeaders
    Body = $atBody
    WebSession = $idpSession
}
# Use a try catch block to make the request.
try
{
    Write-Host ("Getting CyberArk Auth Token from:  {0}" -f $authURL)
    $atResult = Invoke-WebRequest @atWebRequestOptions

    # Convert the result into JSON.
    $atJSON = ConvertFrom-Json $atResult

    Write-Verbose ("Auth Token:  {0}" -f $atJSON)
}
catch
{
    Write-Warning ("Failed to retrieve Auth Token from:  {0}" -f $authURL)
    Write-Warning ("Auth Token Result:  {0}" -f $atResult)
    Write-Warning $_
    Exit $LASTEXITCODE
}

### End Section ###
#endRegion

#region Get Accounts
### Loop over accounts ###
# Loop over the accounts
foreach ($acctKey in $Accounts.Keys)
{
    # Extract the Source and Target.
    $_sourceAcct = $Accounts[$acctKey].Source
    $_targetAcct = $Accounts[$acctKey].Target

    # Get Source account password from CyberArk.
    #region Get Account from CyberArk
    try
    {
        # Decode the source account.
        $_attribsSource = $_sourceAcct.Split("/")

        # Set the attributes
        $_sourceType  = $_attribsSource[0]
        $_sourceVault = $_attribsSource[2]
        $_sourceName  = $_attribsSource[3]

        Write-Host ("Getting account:  Type ({0}) : Vault ({1}) : Name ({2})" -f $_sourceType, $_sourceVault, $_sourceName)

        # Query CyberArk for the account ID.
        #region Find Accounts
        # Build the Headers and Body
        $faHeaders = @{
            'Accept' = 'application/json'
            'Authorization' = $atJSON
        }

        # Set the Query and Filter attributes
        $filter = ("safename eq {0}" -f $_sourceVault)
        $search = ("{0}" -f $_sourceName)

        # Only using the filter here.  The API search is limited.
        $faURL = $PVWAURL + "/PasswordVault/API/Accounts?filter=$($filter)"

        # Build the web request options.
        $faWebRequestOptions = @{
            UseBasicParsing = $null
            Uri = $faURL
            TimeoutSec = $RequestTimeout
            ContentType = "application/json"
            Method = "GET"
            Headers = $faHeaders
            WebSession = $idpSession
        }
        # Use a try catch block to make the request.
        try
        {
            Write-Host ("Getting account(s) from:  {0}" -f $faURL)
            $faResult = Invoke-WebRequest @faWebRequestOptions

            # Convert the result into JSON.
            $faJSON = ConvertFrom-Json $faResult

            Write-Host ("Found Account(s):  {0}" -f $faJSON.count)

        }
        catch
        {
            Write-Warning ("Failed to retrieve account(s) from:  {0}" -f $faURL)
            Write-Warning ("Account Search Result:  {0}" -f $faResult)
            Write-Warning $_
            Exit $LASTEXITCODE
        }

        # Check the result
        if ($faJSON.count -gt 0)
        {
            # Filter the found accounts on the "Name" attribute
            foreach ($_acct in $faJSON.value)
            {
                # Check to see if the object name matches the requested name.
                $_acctName = $_acct.name

                if ($_acctName -ieq $_sourceName)
                {
                    # Set the found account and break out of the loop.
                    $_foundAccounts = $_acct
                    break
                }
            }
            

            Write-Host ("Selected Account:  {0}" -f $_foundAccounts)
        }
        else
        {
            # Exit if nothing found.
            Write-Warning ("No Accounts Found!")
            Exit
        }

        if (($null -eq $_foundAccounts) -or ($_foundAccounts -eq ""))
        {
            # Check to see if no accounts were found.
            Exit
        }
        
        #endRegion Get Accounts

        # Get the password for the found account.
        #region Retrieve Password
        # Build the Headers and Body
        $rpHeaders = @{
            'Accept' = 'application/json'
            'Authorization' = $atJSON
        }

        $rpBody = @{
            #
        }

        # Pull the account ID from the found accounts.
        $accountID = $_foundAccounts.id

        # https://<IIS_Server_Ip>/PasswordVault/API/Accounts/{accountId}/Password/Retrieve/
        $rpURL = $PVWAURL + "/PasswordVault/API/Accounts/$($accountID)/Password/Retrieve/"

        # Build the web request options.
        $rpWebRequestOptions = @{
            UseBasicParsing = $null
            Uri = $rpURL
            TimeoutSec = $RequestTimeout
            ContentType = "application/json"
            Method = "POST"
            Headers = $rpHeaders
            #Body = $rpBody
            WebSession = $idpSession
        }
        # Use a try catch block to make the request.
        try
        {
            Write-Host ("Getting password from:  {0}" -f $rpURL)
            $rpResult = Invoke-WebRequest @rpWebRequestOptions

            # Convert the result into JSON.
            $rpJSON = ConvertFrom-Json $rpResult

            Write-Verbose ("Password:  {0}" -f $rpJSON)
        }
        catch
        {
            Write-Warning ("Failed to retrieve password from:  {0}" -f $rpURL)
            Write-Warning ("Password Retrieval Result:  {0}" -f $rpResult)
            Write-Warning $_
            Write-Host ("      Safe Name  :  {0}" -f $_foundAccounts.safeName)
            Write-Host ("    Object Name  :  {0}" -f $_foundAccounts.name)
            Write-Host ("     Account ID  :  {0}" -f $_foundAccounts.id)
            Write-Host ("      User Name  :  {0}" -f $_foundAccounts.userName)
            Write-Host ("        Address  :  {0}" -f $_foundAccounts.address)
            Write-Host ("    Secret Type  :  {0}" -f $_foundAccounts.secretType)
            Write-Host ("Assigned Platform:  {0}" -f $_foundAccounts.platformId)
            
            Exit $LASTEXITCODE
        }

        $_newPassword = $rpJSON
    }
    catch
    {
        Write-Warning ("Error processing account:  {0}" -f $_sourceAcct)
        Write-Error $_

        # If there is an error getting the account then exit this loop.
        break
    }
    #endRegion Retrieve Password
    #endRegion

    # Set Target account password in 1 Password.
    #region Set Account in 1 Password.
    try
    {
        # Decode the target account.
        $_attribsTarget = $_targetAcct.Split("/")

        # Set the attributes.
        $_targetType  = $_attribsTarget[0]
        $_targetVault = $_attribsTarget[2]
        $_targetName  = $_attribsTarget[3]

        Write-Host ("setting password in 1 Password for:  Type ({0}) : Vault ({1} : Name ({2}))" -f $_targetType, $_targetVault, $_targetName)

        # Make the call
        $resultSet = op item edit "$($_targetName)" --vault "$($_targetVault)" "password=$($_newPassword)"

        Write-Host ("Set Result:  {0}" -f $resultSet)
    }
    catch
    {
        Write-Warning ("Error setting password for:  {0}" -f $_targetAcct)
        Write-Error $_

        # If there is an error setting the account then exit this loop.
        break
    }
    
    #endRegion

}

### End Section ###
#endRegion

#region Log Off
### Log Off ###
# Build the Headers and Body
$loHeaders = @{
    'Accept' = 'application/json'
    'Authorization' = $atJSON
}

$loURL = $PVWAURL + "/PasswordVault/API/Auth/Logoff/"

# Build the web request options.
$loWebRequestOptions = @{
    UseBasicParsing = $null
    Uri = $loURL
    TimeoutSec = $RequestTimeout
    ContentType = "application/x-www-form-urlencoded"
    Method = "POST"
    Headers = $loHeaders
    WebSession = $idpSession
}
# Use a try catch block to make the request.
try
{
    Write-Host ("Logging off of CyberArk using   :  {0}" -f $loURL)
    $loResult = Invoke-WebRequest @loWebRequestOptions

}
catch
{
    Write-Warning ("Failed to retrieve Auth Token from:  {0}" -f $loURL)
    Write-Warning ("Auth Token Result:  {0}" -f $loResult)
    Write-Warning $_
    Exit $LASTEXITCODE
}
### End Section ###
#endRegion