<#
    .SYNOPSIS
    Stops all services listed for each server, Updates the Password, and Starts all services.

    .DESCRIPTION
    Requires PowerShell 7+, psPAS 6.4.85+, Custom Logging Module, and Custom Utilities Module.
    This script leverages a configuration file to interface with the CyberArk PVWA and then it reads
    the provided CSV file(s).  Each line should contain the server, service, and account to be used.
    All input files will be combined, sorted, and deduped based on the Hostname and ServiceName.
    Uses psPAS Version '6.4.85' module from Pete Mann.  https://pspas.pspete.dev/
    Command Line Parameters override the configuration file settings.

    .PARAMETER ConfigFile
    [string]:   This is the relative or fully qualified path to the Configuration file.  This is a
                PowerShell Data File (PSD1).
                If not specified then a default file will be created.

    .PARAMETER LogLevel
    [string]:   This sets the level of logging to the console and to the log file.
                The values are listed in order.  All levels above the one that is set will be output.
        Valid Values:
            Force   :  Always printed.
            None    :  Prints None, and Force.
            Critical:  Prints Critical, None, and Force
            Error   :  Prints Error, Critical, None, and Force
            Warning :  Prints Warning, Error, Critical, None, and Force
         Information:  Prints Information, Warning, Error, Critical, None, and Force
            Debug   :  Prints Debug, Information, Warning, Error, Critical, None, and Force
            Verbose :  Prints Verbose, Debug, Information, Warning, Error, Critical, None, and Force
            Trace   :  Prints Trace, Verbose, Debug, Information, Warning, Error, Critical, None, and Force

    .PARAMETER LogFolder
    [string]:   The relative or fully qualified path to a folder where the log files will be written.
                Defaults:  .\Logs

    .PARAMETER LogFile
    [string]:   The Name of the log files.  The date will be prefixed onto the filename.
                Defaults:  YYYY-MM-DD_Logger.log

    .PARAMETER InputFiles
    [string[]]: This is one or more CSV file(s) that contain the Servers, Services, and Target accounts.

    .PARAMETER OutFile
    [string]:   This is the filename to write the results to, in a CSV format.  If not provided the Input filename will be used
                with the word OUT appended to the name. <-- Not working yet.
                Need to figure out a way to report back the data from the functions.

    .PARAMETER ThumbPrint
    [string]:   This is the thumbprint of the client certificate to be used during the
                authentication process.

    .PARAMETER AllowCPMDisabled
    [bool]:     If the targeted service account is in a CPM Disabled state, should the script continue?

    .PARAMETER MaxCPMWait
    [int]:      The time in seconds to wait for the CPM to finish changing the targeted service account's password(s).
                Once the time expires, you will be asked if you would like to keep waiting.

    .PARAMETER Help
    [switch]:   Displays Help information.

    .PARAMETER RotateServicePassword
    [bool]:     If True, the targeted service account's password will be rotated by the CPM.

    .INPUTS
    None

    .OUTPUTS
    None

    .NOTES
    This script leverages the work of the following people and others.
        https://github.com/allynl93
        https://github.com/infamousjoeg
        https://github.com/pspete

    This script will read the following attributes from the configuration file.
    Section Name:       Attribute Name
    CyberArk_PVWA
                    HTTP_Scheme     :  HTTP/HTTPS
                    Address         :  IP address, Short Name, Fully Qualified Name
                    Port            :  TCP port number
                    IIS_Application :  The name of the Web Site in IIS
                    IgnoreSSLErrors :  Ignore any certificate errors
                    User_Authentication:  The type of authentication to be used with the PVWA
    Logging
                    Level           :  The logging level
                    Folder          :  The folder to store log files in
                    Filename        :  The name to use for log files
    Inputs
                    InputFiles      :  An array list of files to be read from
                    OutFile         :  The file to write the output information to
                    ThumbPrint      :  The thumbprint of the X.509 Client Certificate to use for authentication
                    AllowCPMDisabled:  True or False
                    MaxCPMWait      :  Time in seconds
                    Reason          :  The reason for checking out the accounts from CyberArk Enterprise Password Vault
                    Unlock          :  Forcibly unlock the targeted service accounts if they are locked
                    RotateServicePassword:  Initiate a CPM change task
    Threads
                    Max             :  The number of background threads to use.  Split up on Hostname.  0 = Disabled

    This script leverages the following modules.
    1. Logger : This is a custom PowerShell logging module.
                

    .EXAMPLE
        PS> .\Set-WindowsServiceAccount.ps1

    .EXAMPLE
        PS> .\Set-WindowsServiceAccount.ps1 -ConfigFile ".\Conf\Test_Config.psd1
        
#>

# Import the required modules.
#  Logger is a custom logging module that needs to be placed in your PowerShell Modules path.
Using module Logger
#  Utilities is a custom PowerShell module that needs to be in your PowerShell Moduels path.
Using module Utilities

#Using module "Modules\CustomWebRequest.psm1"

[CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $ConfigFile,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string[]] $InputFiles,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
            [ValidateSet ("Force", "None", "Critical", "Error", "Warning", "Information", "Debug", "Verbose", "Trace")]
        [string] $LogLevel,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $LogFolder,
        
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $LogFile,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $OutFile,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $ThumbPrint,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [bool] $AllowCPMDisabled,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [int] $MaxCPMWait,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [int] $Reason,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false
        )]
        [switch] $Help,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false
        )]
        [bool] $RotateServicePassword
    )

# Import PsPas module.  This simplifies talking to the CyberArk REST API.
Import-Module psPAS -Force -MinimumVersion 6.4.85

# Import PS-SAML-Interactive.  If using SAML authentication, uncomment this.
#  This can be downloaded from here:  https://github.com/allynl93/getSAMLResponse-Interactive
#Import-Module ".\PS-SAML-Interactive.psm1"

########################################
#region Force Verbose/Debug/Information
########################################
# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_preference_variables?view=powershell-7.4

# This will allow the output of any messages written with Write-Verbose.
# For Verbose logging you can run the script with the -Verbose switch.
# To enable verbose logging you can uncomment the following line.
#$VerbosePreference='Continue'

# To disable verbose logging after forcing it on you can uncomment the following line.
#$VerbosePreference='SilentlyContinue'

# This will allow the output of any messages written with Write-Debug.
# For Debug logging you can run the script with the -Debug switch.  Though it will pause at each message.
# To enable debug logging you can uncomment the following line.  This does not pause at each message.
#$DebugPreference='Continue'

# To disable debug logging after forcing it on you can uncomment the following line.
#$DebugPreference='SilentlyContinue'


# This will allow the output of any messages written with Write-Information.
# For Verbose logging you can run the script with the -InformationAction Continue.
# To enable information logging you can uncomment the following line.
#$InformationPreference='Continue'

# To disable debug logging after forcing it on you can uncomment the following line.
#$InformationPreference='SilentlyContinue'

#endRegion Force Verbose/Debug
########################################
########################################
#region Set Console Back Ground Color
########################################
#[console]::BackGroundColor = 'Black'
#Clear-Host
#endRegion Set Console Back Ground Color
########################################
########################################
#region Script Variables
########################################
# Get the path the script was launched from.
$_startingPath = (Get-Location).Path

# Get the start time of the script.
$_startTime = Get-Date

# The default folder for the configuration file.
$_configPath = "Conf"

# The default configuration filename.
$_configFileName = "Default_Configuration_File.psd1"

# This variable holds the psPAS session.
$_pasSession = $null

#endRegion Script Variables
########################################
########################################
#region CyberArk Functions
########################################
function New-CyberArkSession
{
    <#
        .DESCRIPTION
        Uses psPAS to create a new REST API session with the CyberArk Password Vault Web Access
        (PVWA) server.

        .PARAMETER AuthMethod
        [string]    The type of authentication to be used when creating the new session.
                    Supports:
                        PKI:    Public Key Infrastructure.  X.509 certificate with the Enhanced Key
                                Usage of Client Authentication (1.3.6.1.5.5.7.3.2)
                        PKIPN:  Public Key Infrastructure with Pin. X.509 certificate with the Enhanced Key
                                Usage of Client Authentication (1.3.6.1.5.5.7.3.2) that is stored on a
                                Smart Card or YubiKey, and requires a personal Pin number to access.
                    CyberArk:   Not Implemented.  This uses a local CyberArk user to authenticate with.
                        LDAP:   Not Implemented.  This uses a domain based account to authenticate with.
                        SAML:   Not Implemented.  This uses Single Sign On to authenticate with.
                                This requires using an additional package and exe to work.
        .PARAMETER Address
        [string]    The short name, fully qualified domain name (FQDN), or IP address of the PVWA server.
        
        .PARAMETER Scheme
        [string]    The HTTP Method to use.  HTTP or HTTPS.
        
        .PARAMETER Port
        [int]       The TCP port to use when connecting to the PVWA server.  Default 443.
        
        .PARAMETER Application
        [string]    The Application name within IIS that is being used.  Default PasswordVault.
        
        .PARAMETER IgnoreSSLErrors
        [bool]      True or False.  If True, SSL / TLS certificate errors will be ignored.
        
        .PARAMETER ThumbPrint
        [string]    If using PKI or PKIPN authentication then the certificate thumb print can be specified.
                    This will be used for authentication to the PVWA server.
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
            [ValidateSet ("CyberArk", "LDAP", "SAML", "PKI", "PKIPN")]
        [string] $AuthMethod,

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $Address,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $Scheme = "https",

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [int] $Port = 443,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $Application = "PasswordVault",

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [bool] $IgnoreSSLErrors = $false,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $ThumbPrint
    )

    # Status message
    $Logger.Write(("Requested Authentication Method:  {0}" -f $AuthMethod.ToUpper()), "Debug")

    # Build the URI.
    $_targetURI = [System.UriBuilder]::new($Scheme, $Address, $Port)
    $Logger.Write(("New URI Created:  {0}" -f $_targetURI.Uri.AbsoluteUri), "Debug")

    # Create the session result variable.
    $_sessionResult = $null

    # Choose the authentication mehtod flow.
    if ($AuthMethod -ieq "CyberArk")
    {
        # CyberArk
        
    }
    elseif ($AuthMethod -ieq "LDAP")
    {
        # LDAP
    }
    elseif ($AuthMethod -ieq "SAML")
    {
        # SAML
    }
    elseif ($AuthMethod -ieq "PKI")
    {
        # PKI
        $_sessionResult = Get-Session_PKI -URI $_targetURI.Uri -ThumbPrint $ThumbPrint -IgnoreSSLErrors $IgnoreSSLErrors
    }
    elseif ($AuthMethod -ieq "PKIPN")
    {
        # PKIPN
        $_sessionResult = Get-Session_PKIPN -URI $_targetURI.Uri -ThumbPrint $ThumbPrint -IgnoreSSLErrors $IgnoreSSLErrors
    }
    else
    {
        # Invalid
    }

    # Save the PAS Session
    $Logger.Write(("Saving psPAS session."), "Debug")
    $_pasSession = Get-PASSession

    # Clear cookies if using PKI or PKIPN.  This avoids an API error in later calls.
    if ((($AuthMethod -ieq "PKI") -or ($AuthMethod -ieq "PKIPN")) -and ($null -ne $_pasSession))
    {
        $Logger.Write(("Clearing cookies from psPAS session."), "Debug")

        $_theWebSession = $_pasSession.WebSession

        # Clear the cookies of the PAS Session.  This is needed to avoid getting a 401 (Unauthorized)
        if ($_pasSession.Keys.Contains("WebSession"))
        {
            # The WebSession property exists.
            if ($null -ne $_pasSession["WebSession"].cookies)
            {
                # There are cookies.
                $_pasSession["WebSession"].cookies = [System.Net.CookieContainer]::New()
            }
            else
            {
                # There are no cookies.
                $Logger.Write("The PAS Session has a Web Session that does not have any Cookies!", "Warning")
            }
        }
        else
        {
            $Logger.Write("The PAS Session does not contain the Web Session!", "Warning")
        }
        
    }

    # Return result.
    return $_sessionResult
}

function Get-Session_PKIPN
{
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [uri] $URI,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $Application = "PasswordVault",

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [bool] $IgnoreSSLErrors = $false,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $ThumbPrint
    )

    # Create a variable to hold the target thumbprint.
    $_targetThumbPrint = $ThumbPrint

    # Adding the System.Security assembly manually.  This avoids an occasional failure.
    Add-Type -AssemblyName System.Security

    # Get ALL Certificates in the current user's certificate store.  It must have a private key and be marked for Client Authentication.
    $myCerts = [System.Security.Cryptography.X509Certificates.X509Certificate2[]](Get-ChildItem Cert:\CurrentUser\My -EKU "*Client Authentication*")

    # Remove expired certificates.  If they are not expired within the next 10 minutes.
    $validThrough = (Get-Date) + (New-TimeSpan -Minutes 10)
    [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$validCerts = $myCerts | Where-Object {$_.NotAfter -gt $validThrough -and $_.HasPrivateKey}

    # Check if a ThumbPrint was specified.  If not ask!
    if (($null -eq $_targetThumbPrint) -or ($_targetThumbPrint -eq ""))
    {
        # Test if more than one certificate was returned.
        if ($validCerts.Count -gt 1)
        {
            # Open a dialog box for the user to select from.
            $Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2UI]::SelectFromCollection(
                $validCerts,
                'Choose a certificate',
                'Choose a certificate',
                'SingleSelection'
            )
            $_targetThumbPrint = $Cert[0].ThumbPrint
        }
    }
    else
    {
        # Verify the provided thumb print can be found in the valid certificates.
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$targetCert = $validCerts | Where-Object {$_.Thumbprint -eq $ThumbPrint}

        # There should only be one.  If it is not found the target thumb print is set to null.
        $_targetThumbPrint = $targetCert[0].ThumbPrint

    }

    # Check to see if the user canceled the certificate selection window.
    if ($null -eq $_targetThumbPrint)
    {
        $Logger.Write("User canceled certificate selection window or provided thumbprint not found!", "Error")
        exit 200
    }

    # Build the request parameters for creating a new psPAS session.
    $_pasSessionAttributes = @{
        BaseURI = $URI.AbsoluteUri
        PVWAAppName = $Application
        CertificateThumbprint = $_targetThumbPrint
        ConcurrentSession = $true
        Type = "PKIPN"
    }

    # If IgnoreSSLErrors is true add it.
    if ($IgnoreSSLErrors)
    {
        $_pasSessionAttributes.Add("SkipCertificateCheck", $IgnoreSSLErrors)
    }

    # Make the request.
    $_newpsPASSession = New-PASSession @_pasSessionAttributes

    return $_newpsPASSession
}
function Get-Session_PKI
{
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [uri] $URI,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $Application = "PasswordVault",

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [bool] $IgnoreSSLErrors = $false,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $ThumbPrint
    )

    # Create a variable to hold the target thumbprint.
    $_targetThumbPrint = $ThumbPrint

    # Adding the System.Security assembly manually.  This avoids an occasional failure.
    Add-Type -AssemblyName System.Security

    # Get ALL Certificates in the current user's certificate store.  It must have a private key and be marked for Client Authentication.
    $myCerts = [System.Security.Cryptography.X509Certificates.X509Certificate2[]](Get-ChildItem Cert:\CurrentUser\My -EKU "*Client Authentication*")

    # Remove expired certificates.  If they are not expired within the next 10 minutes.
    $validThrough = (Get-Date) + (New-TimeSpan -Minutes 10)
    [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$validCerts = $myCerts | Where-Object {$_.NotAfter -gt $validThrough -and $_.HasPrivateKey}

    # Check if a ThumbPrint was specified.  If not ask!
    if (($null -eq $_targetThumbPrint) -or ($_targetThumbPrint -eq ""))
    {
        # Test if more than one certificate was returned.
        if ($validCerts.Count -gt 1)
        {
            # Open a dialog box for the user to select from.
            $Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2UI]::SelectFromCollection(
                $validCerts,
                'Choose a certificate',
                'Choose a certificate',
                'SingleSelection'
            )
            $_targetThumbPrint = $Cert[0].ThumbPrint
        }
    }
    else
    {
        # Verify the provided thumb print can be found in the valid certificates.
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$targetCert = $validCerts | Where-Object {$_.Thumbprint -eq $ThumbPrint}

        # There should only be one.  If it is not found the target thumb print is set to null.
        $_targetThumbPrint = $targetCert[0].ThumbPrint

    }

    # Check to see if the user canceled the certificate selection window.
    if ($null -eq $_targetThumbPrint)
    {
        $Logger.Write("User canceled certificate selection window or provided thumbprint not found!", "Error")
        exit 200
    }

    # Build the request parameters for creating a new psPAS session.
    $_pasSessionAttributes = @{
        BaseURI = $URI.AbsoluteUri
        PVWAAppName = $Application
        CertificateThumbprint = $_targetThumbPrint
        ConcurrentSession = $true
        Type = "PKI"
    }

    # If IgnoreSSLErrors is true add it.
    if ($IgnoreSSLErrors)
    {
        $_pasSessionAttributes.Add("SkipCertificateCheck", $IgnoreSSLErrors)
    }

    # Make the request.
    $_newpsPASSession = New-PASSession @_pasSessionAttributes

    return $_newpsPASSession
}

function Get-CyberArkAccount
{
    <#
        .DESCRIPTION
        This function searches for an account and gets the account details.  There is
        an option to forcibly unlock the account if it is locked.  Unlocking the account
        forcefully will not rotate the accounts password.

        .PARAMETER Safename
        [string]    This is the name of the safe that holds the account in CyberArk.

        .PARAMETER Address
        [string]    This is the address of the account in CyberArk.

        .PARAMETER Username
        [string]    This is the username of the account in CyberArk.

        .PARAMETER Unlock
        [bool]      This is True or False.  If True, the account will be forcibly 
                    unlocked.  This does not rotate the account's password.

        .OUTPUTS
        [hashtable] A hash table is returned that has the following attributes.
                    IsSuccess       [bool] True or False.  True if successful.
                    Credential      [pscredential] null.
                    LogonDomain     [string] The value stored in the Account's Lodon Domain field.
                    AllAttributes   [pscustom] A custom PowerShell object containing the details
                                    returned by the psPAS Get-AccountDetails.
                    ID              [string] The ID of the account in CyberArk.
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $Safename,

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $Address,

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $Username,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [bool] $Unlock = $false
    )

    # Create the response object.
    $_respObj = @{
        IsSuccess = $false
        Credential = $null
        LogonDomain = $null
        AllAttributes = $null
        ID = $null
    }

    # Create a variable to hold the details of the target account.
    $_targetAccount = $null

    # Make the call. Force to an object array.  Otherwise 1 result is not an array.
    [object[]]$_accountAttributes = Get-PASAccount -search ("{0} {1}" -f $Username, $Address) -safeName $Safename

    # Check the result.
    if ($null -ne $_accountAttributes)
    {
        # Check the number of accounts returned.  Ideally only 1.
        if ($_accountAttributes.Count -eq 0)
        {
            # No account(s) found.
            $Logger.Write(("Failed! No Accounts Found!.
            `t  Safe  : {0}
            `tAddress : {1}
            `tUsername: {2}" -f $Safename, $Address, $Username), "Error")

            # Return the failed/default response object.
            return $_respObj
        }
        elseif ($_accountAttributes.Count -eq 1)
        {
            # 1 Account found.
            $Logger.Write(("1 Account Found!.  Safe ({0}) : Address ({1}) : Username ({2})" -f $Safename, $Address, $Username), "Information")

            # Set the target account.
            $_targetAccount = $_accountAttributes[0]
        }
        elseif ($_accountAttributes.Count -gt 1)
        {
            # More than 1 account found.
            $Logger.Write(("More than 1 Account Found!.
            `t  Safe  : {0}
            `tAddress :{1}
            `tUsername:{2}" -f $Safename, $Address, $Username), "Warning")

            # Set the target account.  Use the first entry.
            $_targetAccount = $_accountAttributes[0]
        }
    }

    # Test the target account.
    if (($null -ne $_targetAccount) -and ($null -ne $_targetAccount.id) -and ($_targetAccount.id -ne ""))
    {
        # The target account is not null and it has the account ID.  Check if it is locked by getting the account details.
        $_targetDetails = Get-AccountDetails -AccountID $_targetAccount.ID
        
        # Was the account details retrieved successfully?
        if (($null -ne $_targetDetails) -and ($_targetDetails.IsSuccess))
        {
            # We have the account details.  Is the account locked?
            if ($_targetDetails.LockedBy -eq "")
            {
                # The Account is not locked.
            }
            else
            {
                # Account is locked.
                $Logger.Write(("Account is Locked!  
                `t   Safe  : {0}
                `tAddress  : {1}
                `tUsername : {2}
                `t     ID  : {3}
                `tLocked By: {4}" -f $Safename, $Address, $Username, $_targetDetails.ID, $_targetDetails.LockedBy), "Warning")

                # Should an unlock be tried?
                if ($Unlock)
                {
                    # Try to unlock the account.
                    $_unlock = Unlock-CyberArkAccount -AccountID $_targetAccount.ID

                    # Test the unlock
                    if (($null -ne $_unlock) -and ($_unlock.IsSuccess))
                    {
                        # It worked.
                        $Logger.Write("Unlocked the Account.", "Information")
                    }
                    else
                    {
                        # It failed.
                        $Logger.Write(("Failed to Unlock the Account!"), "Error")
                        exit 404
                    }
                }
            }
        }

        $_logonTo = $_targetAccount.platformAccountProperties

        # Update the return object.
        $_respObj["IsSuccess"] = $true
        $_respObj["LogonDomain"] = $_logonTo.LogonDomain
        $_respObj["AllAttributes"] = $_targetAccount
        $_respObj["ID"] = $_targetAccount.id

        # Return the response object.
        return $_respObj
    }
    else
    {
        $Logger.Write("The Target Account was not Set!", "Error")

        # Get the error details.
        $_error = Get-Error

        # Output the error details.
        $Logger.Write(("HTTP Response:  {0}" -f $_error.Exception.Message), "Error")
        $Logger.Write(("Response Data:  {0}" -f $_error.FullyQualifiedErrorID), "Error")
        
        exit 404
    }
}

function Reset-AccountPassword
{
    <#
        .DESCRIPTION
        This function will call the psPAS function to initiate the CPM Change Password within CyberArk.

        .PARAMETER Accounts
        [hashtable] A hashtable containing the accounts to have their passwords changed by CyberArk.

        .OUTPUTS
        [hashtable] A hashtable containing the following values.
                    IsSuccess   True or False.  If True then the call was successful.
                    Results     A hashtable containing the details of the request and its outcome.
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [hashtable] $Accounts
    )
    # Build the return object.
    $_retObj = @{
        IsSuccess = $false
        Results = @{}
    }

    # Rotate the Account password(s)
    $Logger.Write("Rotating the account password(s).", "Information")

    # Loop over the accounts and initiate the account action.
    foreach ($_sc in $Accounts.Keys)
    {
        # Get the account ID.
        $_tID = Set-CyberArkAccountAction -AccountID $Accounts[$_sc].ID -Action Change

        # Status
        $Logger.Write(("Set Account Password Rotation : Success ({0}) : Account ID ({1}) : Message ({2}) : Account ({3})" -f $_tID.IsSuccess, $_tID.ID, $_tID.Message, $_sc), "Information")
    }

    # Password rotation request has been submitted.  Ask the user if we auto wait or User controlled.
    $UsersChoice = Read-Host -Prompt "Automatically Wait for Password Rotation to Complete? [Yes/No]"

    # Use a Do While loop to keep asking after the CPM Max Wait time.
    do
    {
        # Choose the adventure.
        if (($UsersChoice -ieq "Y") -or ($UsersChoice -ieq "Yes"))
        {
            # Wait for password rotation to complete and continue.
            # Wait for rotation to complete.
            $Logger.Write("Waiting for the account password(s) to be rotated.", "Information")

            # The Watch-CPMChange needs work.
            $resultWait = Watch-CPMChange -Accounts $Accounts -Wait $script:_scriptConfig["Inputs"]["MaxCPMWait"]

            # Test the wait result to see if we break out of the loop.
            if (($null -ne $resultWait) -and ($resultWait.IsSuccess))
            {
                # Good to go. Set the result and Break out.
                $_retObj["IsSuccess"] = $true
                $_retObj["Results"] = $resultWait
                break
            }
            else
            {
                $Logger.Write(("Account Password Rotation Status."), "Force")
                # Output the current status for each account.
                foreach ($_targetAccount in $resultWait["AccountStatus"].Keys)
                {
                    # Set the account object.
                    $_targAcct = $resultWait["AccountStatus"][$_targetAccount]

                    # Output the status
                    $Logger.Write(("Account ({0}) : ID ({1}) : Action ({2}) : LockedBy ({3}) : CPM Disabled ({4})" -f $_targetAccount, $_targAcct.ID, $_targAcct.Action, $_targAcct.LockedBy, $_targAcct.CPMDisabled), "Force")
                }

                # Ask if we should keep waiting.
                $UsersChoice = Read-Host -Prompt "Keep waiting? [Yes/No]"

                # Test the user's response.
                if (($UsersChoice -ieq "Y") -or ($UsersChoice -ieq "Yes"))
                {
                    # Keeep waiting.  Restart the loop.
                    $Logger.Write(("User's response ({0}).  Keep Waiting." -f $UsersChoice), "Verbose")
                }
                else
                {
                    # Drop to waiting on user.
                    $Logger.Write(("User's response ({0}).  Stop Waiting." -f $UsersChoice), "Verbose")
                    $_retObj["Results"] = $resultWait
                }
            }
        }
        else 
        {
            # Prompt the user to answer when password rotation completes.  This prompt pauses the script.
            $UsersChoice = Read-Host -Prompt "Press Enter/Return when the password rotation has completed."

            # Use break to exit the loop.
            break
        }
    }
    while ($true)

    # Return the result object.
    return $_retObj
}
function Set-CyberArkAccountAction
{
    <#
        .DESCRIPTION
        This function will request the Action to be performed by the CPM on the Account specified.

        .PARAMETER AccountID
        [string]    This is the CyberArk Account ID of the account to request the CPM action on.

        .PARAMETER Action
        [string]    This is the CPM Action to be performed on the Account specified.
                    Valid Actions:
                        Verify      The Account's password will be verified by the CPM.
                        Change      The Account's password will be changed by the CPM.
                        Reconcile   The Account's password will be forcibly changed by a privileged account.

        .OUTPUTS
        [hashtable] A hashtable containing the following attributes.
                IsSuccess   True or False.
                Message     Blank if successfull.  If request failed, the details returned.
                ID          The Account ID provided.
                Action      The Action requested.
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $AccountID,

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
            [ValidateSet("Verify", "Change", "Reconcile")]
        [string] $Action
    )
    
    # Create the response object.
    $_respObj = @{
        IsSuccess = $false
        Message = $null
        ID = $AccountID
        Action = $Action
    }

    # Build the request properties.
    $_reqProps = @{
        AccountID = $AccountID
    }

    # Add the action to the request properties.
    if ($Action -ieq "Verify")
    {
        $_reqProps.Add("VerifyTask", $true)
    }
    elseif ($Action -ieq "Change")
    {
        $_reqProps.Add("ChangeTask", $true)
    }
    elseif ($Action -ieq "Reconcile")
    {
        $_reqProps.Add("ReconcileTask", $true)
    }

    # Get the last error that occured.  This will be compared later.
    $_lastError = Get-Error

    # Call the psPAS action.
    $_result = Invoke-PASCPMOperation @_reqProps

    # Get the last error that occured.
    $_reqError = Get-Error

    # Compare the error details.
    if ($_lastError -ne $_reqError)
    {
        # Get the last error detials.
        $_lastErrException = $_reqError.Exception

        # Update the response object.
        $_respObj["IsSuccess"] = $false
        $_respObj["Message"] = $_lastErrException.Message
    }
    else
    {
        $_respObj["IsSuccess"] = $true
        $_respObj["Message"] = ""
    }
    
    # Return the response object.
    return $_respObj

}
function Unlock-CyberArkAccount
{
    <#
        .DESCRIPTION
        This function will forcibly unlock the account requested.  The account's password will
        not be rotated / changed.

        .PARAMETER AccountID
        [string]    The ID of the Account in CyberArk.

        .OUTPUTS
        [hashtable] A hashtable containing the following attributes.
                IsSuccess   True or False.
                Message     Blank if successfull.  If request failed, the details returned.
                ID          The Account ID provided.
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $AccountID
    )
    
    # Create the response object.
    $_respObj = @{
        IsSuccess = $false
        Message = $null
        ID = $AccountID
    }

    # Build the request properties.
    $_reqProps = @{
        AccountID = $AccountID
    }

    # Get the last error that occured.  This will be compared later.
    $_lastError = Get-Error

    # Call the psPAS action.  Nothing is returned.
    $null = Unlock-PASAccount @_reqProps -Unlock

    # Get the last error that occured.
    $_reqError = Get-Error

    # Compare the error details.
    if ($_lastError -ne $_reqError)
    {
        # Get the last error detials.
        $_lastErrException = $_reqError.Exception

        # Update the response object.
        $_respObj["IsSuccess"] = $false
        $_respObj["Message"] = $_lastErrException.Message
    }
    else
    {
        $_respObj["IsSuccess"] = $true
        $_respObj["Message"] = ""
    }
    
    # Return the response object.
    return $_respObj

}
function Get-AllAccounts
{
    <#
        .DESCRIPTION
        This function will loop over the Accounts specified and get the details of each account.

        .PARAMETER Accounts
        [object[]]  This is the list of accounts to retrieve.

        .OUTPUTS
        [hashtable] A hashtable containing the account's details for each account.
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [object[]] $Accounts,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [bool] $Unlock = $false
    )
    # Create the return object.
    $_foundAccounts = @{}

    # Loop over the admin creds to get.
    foreach ($_ac in $Accounts)
    {
        # Test for missing properties.
        if (($_ac.Safename -ne "") -and ($_ac.Username -ne "") -and ($_ac.Address -ne ""))
        {
            # Build the unique name
            $_credName = ("{0}/{1}/{2}" -f $_ac.Safename, $_ac.Username, $_ac.Address)

            # Status message
            $Logger.Write(("Getting Account Information:  {0}" -f $_credName), "Information")

            $_accountDetails = Get-CyberArkAccount -Safename $_ac.Safename -Address $_ac.Address -Username $_ac.Username -Unlock $Unlock
            
            # Test the result.
            if (($null -ne $_accountDetails) -and ($_accountDetails["IsSuccess"]))
            {
                # The account retrieval was successfull.  Add it to the table.
                $_foundAccounts.Add($_credName, $_accountDetails)
            }
            else
            {
                # The account retrieval was NOT successfull.
                $Logger.Write(("Failed to retrieve the Account Information!  Details:  {0}" -f $_credName), "Error")
                exit 404
            }
        }
        else
        {
            $Logger.Write(("Failed to generate the search info!  Details:  {0}" -f $_ac), "Error")
        }
    }

    # Return the object.
    return $_foundAccounts
}

function Submit-ReleaseAllAccounts
{
    <#
        .DESCRIPTION
        This function will call the Release / Check-in Account action.  This is only needed if
        Exclusive Account Access is enabled.  If it is not then nothing will happen.
        If Exclusive Access and One Time Password are enabled for this account the account's 
        password will be rotated by the CPM before the account lock is released.

        .PARAMETER Accounts
        [string]    The ID of the Account within CyberArk.

        .OUTPUTS
        [hashtable] A hashtable containing the results of the release action.
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [hashtable] $Accounts
    )
    # Create the return object.
    $_releasedAccounts = @{}

    # Loop over the admin creds to get.
    foreach ($_ac in $Accounts.Keys)
    {
        # Submit the request to release / Check-In the account.
        $_accountDetails = Submit-ReleaseAccount -AccountID $Accounts[$_ac].ID
        
        # Test the result.
        if (($null -ne $_accountDetails) -and ($_accountDetails["IsSuccess"]))
        {
            # The account release was successfull.
            $Logger.Write(("Released the Account!  Account ({0}) : ID ({1})" -f $_ac, $Accounts[$_ac].ID), "Information")
            $_releasedAccounts.Add($_ac, $_accountDetails)
        }
        else
        {
            # The account release was NOT successfull.
            $Logger.Write(("Failed to Release the Account!  Account ({0}) : ID ({1})" -f $_ac, $Accounts[$_ac].ID), "Error")
            $_releasedAccounts.Add($_ac, $_accountDetails)
        }
    }

    # Return the object.
    return $_releasedAccounts
}

function Submit-ReleaseAccount
{
    <#
        .DESCRIPTION
        This function calls the psPAS Unlock-PASAccount function.

        .PARAMETER AccountID
        [string]    The ID of the Account in CyberArk.

        .OUTPUTS
        [hashtable] A hashtable containing the following attributes.
                IsSuccess   True or False.
                Message     Blank if successfull.  If request failed, the details returned.
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $AccountID
    )
    # Build the return object.
    $_respObj = @{
        IsSuccess = $false
        Message = ""
    }

    # Build the request properties.
    $_reqProps = @{
        AccountID = $AccountID
    }

    # Get the last error that occured.  This will be compared later.
    $_lastError = Get-Error

    # Call the psPAS action.
    $_content = Unlock-PASAccount @_reqProps

    # Get the last error that occured.
    $_reqError = Get-Error

    # Compare the error details.
    if ($_lastError -ne $_reqError)
    {
        # Get the last error detials.
        $_lastErrException = $_reqError.Exception

        # Update the response object.
        $_respObj["IsSuccess"] = $false
        $_respObj["Message"] = $_lastErrException.Message
    }
    else
    {
        # Test the content.
        if (($null -ne $_content) -and ($_content -ne ""))
        {
            # Update the return object.
            $_respObj["IsSuccess"] = $true
            $_respObj["Message"] = $_content
        }
        else
        {
            # Update the return object.
            $_respObj["IsSuccess"] = $true
            $_respObj["Message"] = ""
        }
    }

    # Return the results
    return $_respObj
}
function Get-AllAccountContent
{
    <#
        .DESCRIPTION
        This function gets the password for all accounts specified.

        .PARAMETER Accounts
        [hashtable] A hashtable containing the list of accounts to retrieve the passwords for.

        .PARAMETER Reason
        [string]    The resaon for retrieving the account's password.

        .OUTPUTS
        [hashtable] A hashtable containing the details of the account and its password.
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [hashtable] $Accounts,

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $Reason
    )

    # Build the return object.
    $_retObj = @{}

    # Loop over the array of accounts.
    foreach ($_sc in $Accounts.Keys)
    {
        # Get the Account Information from the Table.
        # Write the status.
        $Logger.Write(("Retrieving Credential for Account ({0}) : ID ({1}))" -f $_sc, $Accounts[$_sc].ID), "Verbose")

        # Build the request properties.
        $_reqProps = @{
            AccountID = $Accounts[$_sc].ID
        }

        # If a reason was specified then add it.
        if (($null -ne $Reason) -and ($Reason -ne ""))
        {
            $_reqProps.Add("Reason", $Reason)
        }

        # Get the account Details. Returns Credential[PSCredential], Message[String], IsSuccess[Bool]
        $_acctCred = Get-AccountCredential @_reqProps

        # Test the response.
        if (($null -ne $_acctCred) -and ($_acctCred.IsSuccess))
        {
            # The request was successfull.
            $_retObj.Add($_sc, $_acctCred.Credential)
        }
        else
        {
            # The request failed.
            $Logger.Write(("Failed to retrieve the credential for:  
            `t   Entry  : {0}
            `tAccount ID: {1}
            `tSafename  : {2}
            `t Address  : {3}
            `tUsername  : {4}" -f $_sc, $Accounts[$_sc].ID, $Accounts[$_sc].AllAttributes.Safename, $Accounts[$_sc].AllAttributes.Address, $Accounts[$_sc].AllAttributes.Username), "Error")

            # Exit
            exit 404
        }
    }

    # Return the results
    return $_retObj
}

function Get-AccountCredential
{
    <#
        .DESCRIPTION
        This function calls the psPAS functions for Get-PASAccount and Get-PASAccountPassword.
        If the Logon Domain is specified for the account it will be prefixed to the Username attribute.

        .PARAMETER AccountID
        [string]    The ID of the acccount in CyberArk to retrieve the credential for.

        .PARAMETER Reason
        [string]    The reason for retrieving the account's credential.

        .OUTPUTS
        [hashtable] A hashtable containing the following attributes.
                IsSuccess   [bool] True or False.
                Message     [string] Blank if successfull.  If request failed, the details returned.
                Credential  [pscredential] The account username and password.
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $AccountID,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $Reason
    )
    # Build the return object.
    $_respObj = @{
        IsSuccess = $false
        Credential = $null
        Message = ""
    }

    # Build the request properties.
    $_reqProps = @{
        AccountID = $AccountID
    }

    # Get the account details.
    $_details = Get-PASAccount @_reqProps

    # If a reason was specified then add it.
    if (($null -ne $Reason) -and ($Reason -ne ""))
    {
        $_reqProps.Add("Reason", $Reason)
    }

    # Get the last error that occured.  This will be compared later.
    $_lastError = Get-Error

    # Call the psPAS action.
    $_content = Get-PASAccountPassword @_reqProps

    # Get the last error that occured.
    $_reqError = Get-Error

    # Compare the error details.
    if ($_lastError -ne $_reqError)
    {
        # Get the last error detials.
        $_lastErrException = $_reqError.Exception

        # Update the response object.
        $_respObj["IsSuccess"] = $false
        $_respObj["Message"] = $_lastErrException.Message
    }
    else
    {
        # Test the content.
        if (($null -ne $_content) -and ($_content -ne ""))
        {
            # Build the Username.
            $_username = ""
            if (($null -ne $_details) -and ($_details -ne ""))
            {
                if (($null -ne $_details.platformAccountProperties.LogonDomain) -and ($_details.platformAccountProperties.LogonDomain -ne ""))
                {
                    # A logon domain was specified.
                    $_username = $_details.platformAccountProperties.LogonDomain + "\" + $_content.UserName
                }
                else
                {
                    # A logon domain was not specified.
                    $_username = $_content.UserName
                }
            }
            else
            {
                # A logon domain was not specified.
                $_username = $_content.UserName
            }
            # Build the credential object.
            $_credential = [System.Management.Automation.PSCredential]::New($_username, (ConvertTo-SecureString -String $_content.Password -AsPlainText -Force))

            # Update the return object.
            $_respObj["IsSuccess"] = $true
            $_respObj["Credential"] = $_credential
        }
        else
        {
            # Update the response object.
            $_respObj["IsSuccess"] = $false
            $_respObj["Message"] = "The Response is Blank or NULL!"
        }
    }

    # Return the results
    return $_respObj
}
function Get-AccountDetails
{
    <#
        .DESCRIPTION
        This function calls the psPAS function Get-PASAccountDetails.

        .PARAMETER AccountID
        [string]    The ID of the account in CyberArk.

        .OUTPUTS
        [hashtable] A hashtable containing the details of the account requested.
            Attributes:
                IsSuccess           True or False.
                Message             Only populated if an error occured.
                ID                  The ID of the Account in CyberArk.
                Details             The details of the account.
                ManagedByCPM        True, if the account is managed by a CPM.
                CPMDisabled         If populated the CPM is disabled.  No actions will be performed.
                CPMStatus           The status of the CPM's action on the account.
                CPMErrorDetails     The details of the last error when the CPM attempted an action.
                ImmediateCPMTask    The current CPM task to be performed on the account.
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $AccountID
    )
    #
    # Create the response object.
    $_respObj = @{
        IsSuccess = $false
        Message = $null
        ID = $AccountID
        Details = $null
        ManagedByCPM = $null
        CPMDisabled = $null
        CPMStatus = $null
        CPMErrorDetails = $null
        ImmediateCPMTask = $null
    }

    # Build the request properties.
    $_reqProps = @{
        AccountID = $AccountID
    }

    # Get the last error that occured.  This will be compared later.
    $_lastError = Get-Error

    # Call the psPAS action.
    $_result = Get-PASAccountDetail @_reqProps

    # Get the last error that occured.
    $_reqError = Get-Error

    # Compare the error details.
    if ($_lastError -ne $_reqError)
    {
        # Get the last error detials.
        $_lastErrException = $_reqError.Exception

        # Update the response object.
        $_respObj["IsSuccess"] = $false
        $_respObj["Message"] = $_lastErrException.Message
    }
    else
    {
        $_respObj["IsSuccess"] = $true
        $_respObj["Details"] = $_result.Details
        $_respObj["ManagedByCPM"] = $_result.Details.ManagedByCPM
        $_respObj["CPMDisabled"] = $_result.Details.CPMDisabled
        $_respObj["CPMStatus"] = $_result.Details.CPMStatus
        $_respObj["CPMErrorDetails"] = $_result.Details.CPMErrorDetails
        $_respObj["ImmediateCPMTask"] = $_result.Details.ImmediateCPMTask
        $_respObj["LockedBy"] = $_result.Details.LockedBy
        $_respObj["All"] = $_result
    }
    
    # Return the response object.
    return $_respObj
}

function Watch-CPMChange
{
    <#
        .DESCRIPTION
        This function will watch the accounts specified while waiting for the CPM to perform the
        requested Action.

        .PARAMETER Accounts
        [hashtable] A hashtable of the accounts to watch the CPM action on.

        .PARAMETER Wait
        [int]   The maximum time to wait for the CPM to complete the requested action on.

        .OUTPUTS
        [hashtable] A hashtable containing the following attributes.
                IsSuccess       True or False.
                AccountStatus   [hashtable] The current status of the accounts provided.
                ExitReason      The reason for the exit.
                ForceExit       An unrecoverable error occured and the script should exit.
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [hashtable] $Accounts,

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [int] $Wait
    )

    # Build the return object.
    $_retObj = @{
        IsSuccess = $false
        AccountStatus = @{}
        ExitReason = ""
        ForceExit = $false
    }

    # Setup a copy of the service credential table.
    $_tempCredentials = $Accounts.Clone()

    # Keep Looping if action is pending still
    $_keepLooping = $true

    # Setup an array to track the disabled accounts or Failed change.
    $_cpmDisabledAccounts = [System.Collections.ArrayList]::New()

    # Set loop start time.
    $_doLoopStart = Get-Date

    # Add the maximum wait time to the start time.
    $_doLoopMax = $_doLoopStart.AddMinutes($Wait)

    # Get the currently logged on user information.
    $_currentUserInfo = Get-PASLoggedOnUser

    # Run the loop
    do {
        # Create a list of service accounts that have been rotated.  These will be removed from future loops.
        $_changeCompleted = [System.Collections.ArrayList]::New()

        # Loop over the Service Accounts
        foreach ($_sc in $_tempCredentials.Keys)
        {
            # Get the account Details.
            $_tID = Get-AccountDetails -AccountID $_tempCredentials[$_sc].ID
            $_tGen = Get-PASAccount -id $_tempCredentials[$_sc].ID

            # Create a variable to hold just the details.
            $_tDetails = $_tID.Details
            
            # Seperate out the Details.
            $_theDetails = @(
                ("    Account API ID  : {0}" -f $_tGen.id)
                ("  Account Username  : {0}" -f $_tGen.userName)
                (" UTC Creation Date  : {0}" -f (Get-DateTimeFromUnixSeconds -Seconds $_tDetails.CreationDate))
                ("UTC Last Used Date  : {0}" -f (Get-DateTimeFromUnixSeconds -Seconds $_tDetails.LastUsedDate))
                ("      Last Used By  : {0}" -f $_tDetails.LastUsedBy)
                ("UTC Last Verified On: {0}" -f (Get-DateTimeFromUnixSeconds -Seconds $_tDetails.LastVerifiedDate))
                ("  Last Verified By  : {0}" -f $_tDetails.LastVerifiedBy)
                ("UTC Last Modified On: {0}" -f (Get-DateTimeFromUnixSeconds -Seconds $_tGen.secretManagement.LastModifiedTime))
                ("         Locked By  : {0}" -f $_tDetails.LockedBy)
                ("Immediate CPM Task  : {0}" -f $_tDetails.ImmediateCPMTask)
                ("    Managed by CPM  : {0}" -f $_tDetails.ManagedByCPM)
                ("      CPM Disabled  : {0}" -f $_tDetails.CPMDisabled)
                ("        CPM Status  : {0}" -f $_tDetails.CPMStatus)
                (" CPM Error Details  : {0}" -f $_tDetails.CPMErrorDetails)
                #(": {0}" -f $_tDetails.CPMErrorDetails)
            )
            
            # Output details.
            $Logger.Write(("Watching CPM Change on Account ({0}) : ID ({1}) `r`n`t{2}" -f 
            $_sc, $_tID.ID, ($_theDetails -join "`r`n`t")), "Verbose")

            # Update the Account Status.
            if (($null -ne $_retObj.AccountStatus) -and ($_retObj.AccountStatus.ContainsKey($_sc)))
            {
                # Update the status.
                $_retObj.AccountStatus[$_sc] = @{
                    ID = $_tID.ID
                    Action = $_tID.ImmediateCPMTask
                    LockedBy = $_tID.LockedBy
                    CPMDisabled = $_tID.CPMDisabled
                }
            }
            elseif (($null -ne $_retObj.AccountStatus) -and (!$_retObj.AccountStatus.ContainsKey($_sc)))
            {
                # Add the status
                $_retObj.AccountStatus.Add($_sc, @{
                    ID = $_tID.ID
                    Action = $_tID.ImmediateCPMTask
                    LockedBy = $_tID.LockedBy
                    CPMDisabled = $_tID.CPMDisabled
                })
            }
            

            # Test status of account.
            if (($null -ne $_tID) -and ($_tID.IsSuccess))
            {
                # Test the Account status
                if ($_tID.CPMDisabled -ne "")
                {
                    # The CPM is disabled.  Should it be considered finished?
                    if ($script:_scriptConfig["Inputs"]["AllowCPMDisabled"])
                    {
                        # Add account to the list to be removed.
                        $_changeCompleted.Add($_sc)
                    }
                    else
                    {
                        # Allow CPM Disabled is False.  Set force exit.
                        $_retObj.ForceExit = $true

                        # Output status.
                        $Logger.Write(("Account is CPM Disabled!  Account ({0}) : ID ({1}) : Disabled ({2}) : Last Error ({3})" -f $_sc, $_tID.ID, $_tID.CPMDisabled, $_tID.CPMErrorDetails), "Warning")
                    }

                    # Add to the list of CPM Disabled.
                    $_cpmDisabledAccounts.Add($_tID)
                }
                else
                {
                    # CPM is NOT disabled.  Test CPM Task.
                    if (($null -ne $_tID.ImmediateCPMTask) -and ($_tID.ImmediateCPMTask -ne ""))
                    {
                        # Immediate Task is still set.  Keep looping.
                    }
                    else
                    {
                        # Immediate Task is not set.  Test if it is locked.
                        if ($null -eq $_tID.Details.LockedBy)
                        {
                            # Output status.
                            $Logger.Write(("Account Locked!  Account ({0}) : ID ({1}) : Locked By ({2})" -f $_sc, $_tID.ID, $_tID.Details.LockedBy), "Warning")

                            # The account is locked.  Test if the current user has it locked.  If not unlock it.
                            if ($_tID.Details.LockedBy -ine $_currentUserInfo.Username)
                            {
                                # Forcibly unlock the account.  The current user does need those permissions.
                                $_ulAcResult = Unlock-PASAccount -AccountID $_tID.ID

                                # Test unlock result.
                                $Logger.Write(("Account UnLocked!  Account ({0}) : ID ({1})" -f $_sc, $_tID.ID), "Information")
                            }
                            else
                            {

                            }
                        }

                        # Add account to the list to be removed.
                        $_changeCompleted.Add($_sc)
                    }
                }
            }
            else
            {
                # Result is null or failed.
                $Logger.Write(("Failed to get Account details for ({0}) : ID ({1})" -f $_sc, $_tempCredentials[$_sc].ID), "Verbose")
            }

            # Clear the variable.
            $_tID = $null
        }

        # Remove accounts that have completed the action or that have CPM disabled.
        foreach ($_accountToRemove in $_changeCompleted)
        {
            $_tempCredentials.Remove($_accountToRemove)
        }

        # Test the number of pending account actions.
        if ($_tempCredentials.Count -gt 0)
        {
            # Keep Looping
            $Logger.Write(("Accounts pending action:  {0}" -f $_tempCredentials.Count), "Force")

            # Wait
            Start-Sleep -Seconds 10
        }
        else
        {
            # Exit
            $_keepLooping = $false
            $_retObj.IsSuccess = $true

        }

        # Test the current time against the maximum wait time.
        $_currentLoopTime = Get-Date

        if ($_currentLoopTime.Ticks -gt $_doLoopMax.Ticks)
        {
            # Exit
            $_keepLooping = $false
        }

    }
    while ($_keepLooping)

    # Return the results.
    return $_retObj
}
#endRegion CyberArk Functions
########################################
########################################
#region Windows Server Functions
########################################
function Set-ServiceProperties
{
    <#
        .DESCRIPTION
        This function will loop over the Targeted Services and set the requested action on the
        Windows service account.

        .PARAMETER MaxThreads
        [int]   If 0 no sub / job threads will be created.  This is split on the Hostname.
                If greater than 0 then the number of background threads will be created.

        .PARAMETER Action
        [string]    The action to be performed on the service.

        .PARAMETER AdminCreds
        [hashtable] A hashtable containing the credentials needed to authenticate to the target server.

        .PARAMETER ServiceCreds
        [hashtable] A hashtable containing the credentials needed to run the target service.

        .PARAMETER TargetServices
        [hashtable] A hashtable containing the Host information and the Services to perform the
                    requested action on.
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false
            )]
        [int] $MaxThreads,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false
            )]
            [ValidateSet("Start", "Stop", "ReStart", "Update", "Disable", "Automatic", "Delayed", "Manual", "Status")]
        [string] $Action,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false
            )]
        [hashtable] $AdminCreds,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false
            )]
        [hashtable] $ServiceCreds,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false
            )]
        [object[]] $TargetServices
    )
    
    # Check if Threading was requested.
    if ($MaxThreads -gt 0)
    {
        # Call the threaded function
        return Set-ServicePropertiesThreaded @PSBoundParameters
    }
    else
    {
        # Process the input data.
        # Build the default objects.
        $_uniqueHostsAdmins = @{} # This will hold the Unique Host Names and Admin IDs.
        $_uniqueServiceIDs = @{}  # This will hold the Service information and Service IDs.

        # Create a list of Service Status States.
        $serviceStates = @("Paused", "Running", "Stopped")

        # Check if the Target Services were provided.
        if (($null -ne $TargetServices) -and ($TargetServices.Count -gt 0))
        {
            # At least 1 target service provided.  Build the unique targets.
            #  Get the unique host entries and the administrative ID names.  AdminSafe, AdminUser, AdminAddress
            $_uniqueHostsAdmins = $TargetServices | Sort-Object Hostname -Unique | Select-Object Hostname, HostFqdn, HostIP, @{Name="AdminCred"; Expression={$($_.AdminSafe) + "/" + $($_.AdminUser) + "/" + $($_.AdminAddress)}}, TimeOut

            # Get the unique Host and Service entries with the service ID names. ServiceSafe,ServiceUser,ServiceAddress -Unique
            $_uniqueServiceIDs = $TargetServices | Sort-Object Hostname, ServiceName -Unique | Select-Object Hostname, HostFqdn, HostIP, ServiceName, TimeOut, @{Name="ServiceCred"; Expression={$($_.ServiceSafe) + "/" + $($_.ServiceUser) + "/" + $($_.ServiceAddress)}}

            # Loop over the Unique Hosts.
            foreach ($targetHost in $_uniqueHostsAdmins)
            {
                # Output the host information 
                $Logger.Write(("Target: Host Name ({0}) | FQDN ({1}) | IP ({2})" -f $targetHost.Hostname, $targetHost.HostFqdn, $targetHost.HostIP), "Force")

                # Get the Services for this host.
                $_targetedServices = $_uniqueServiceIDs | Where-Object Hostname -ieq $targetHost.Hostname

                # Output the number of services.
                $Logger.Write(("Services Found:  {0}" -f $_targetedServices.Count), "Force")

                # Create a remote PowerShell session variable.
                $session = $null

                # Check for an existing PowerShell session.  Filter on the host's FQDN and the state.
                $_allSessions = (Get-PSSession) | Where-Object ComputerType -eq RemoteMachine
                $_hostPSVSessions = (Get-PSSession -ComputerName $targetHost.HostFqdn -ErrorAction SilentlyContinue) | Where-Object {($_.ConfigurationName -like "PowerShell.7*")}
                $_hostPSASessions = ($_hostPSVSessions) | Where-Object {($_.State -eq "Opened")}
                $_availSessions = $_hostPSASessions | Where-Object Availability -eq Available

                $Logger.Write(("Below is information on All Remote PowerShell Sessions for Host ({0})." -f $targetHost.HostFqdn), "Verbose")
                $Logger.Write(("      All sessions for the target host  :  {0}" -f $_allSessions.Count), "Verbose")
                $Logger.Write(("Sessions where PowerShell.7 is specified:  {0}" -f $_hostPSVSessions.Count), "Verbose")
                $Logger.Write(("    Sessions that are in an Open state  :  {0}" -f $_hostPSASessions.Count), "Verbose")
                $Logger.Write((" Sessions that are marked as Available  :  {0}" -f $_availSessions.Count), "Verbose")

                # Test the results.
                if ($_availSessions.Count -gt 0)
                {
                    # Output startup message.
                    $Logger.Write(("Re-Use Existing Connection ({0})." -f $targetHost.HostFqdn), "Information")

                    # Re-use a session.  There can be multiple sessions but we only need one.
                    $session = $_allSessions[0]
                }
                else
                {
                    # Output startup message.
                    $Logger.Write(("Connecting to host ({0})." -f 
                    $targetHost.HostFqdn), "Information")
                    
                    # Create the session.
                    $session = New-PSSession -ComputerName $targetHost.HostFqdn -Credential $AdminCreds[$targetHost.AdminCred] -ConfigurationName PowerShell.7
                    #-ErrorAction SilentlyContinue
                }

                # Output the session information.
                $Logger.Write(("Session Information:  ID ({0}) | State ({1}) | ConfigurationName ({2}) | Availability ({3}) | Target ({4})" -f
                $session.Id, $session.State, $session.ConfigurationName, $session.Availability, $session.ComputerName), "Debug")

                # Check the session state.
                if ($session.State -ieq 'Opened')
                {
                    # Create a loop counter.
                    $_servLoopCount = 0

                    # Loop over the services
                    foreach ($_targetService in $_targetedServices)
                    {
                        # Increment the loop counter
                        $_servLoopCount++

                        # Output status.
                        $Logger.Write(("Host ({0}) | Service ({1}) | # ({2}) of ({3}) | Action ({4})" -f
                        $_targetService.HostName, $_targetService.ServiceName, $_servLoopCount, $_targetedServices.Count, $Action), "Information")

                        # Clear the error variable.
                        $Error.Clear()

                        # Get the current status of the service.
                        $initialStatus = (Invoke-Command -Session $session -ScriptBlock { 
                                param($ServiceName)
                                Write-Output ("Getting status of ({0}) on ({1}) as ({2})" -f $ServiceName, $(HOSTNAME.EXE), $(whoami.exe))
                                (Get-Service -Name $ServiceName).Status 2>&1
                            } -ArgumentList $_targetService.ServiceName
                            )

                        # Output to the log.
                        $Logger.Write(("{0,24} | Action ({1, 10}) | Service ({2}) | Initial Status `r`n(`r`n`t{3}`r`n)." -f 
                        $_targetService.Hostname, $Action, $_targetService.ServiceName, ($initialStatus -join "`r`n`t")), "Debug")

                        # Invoke Response Variable. Most of the calls do not give a response.
                        $_invokeResponse = $null

                        # Choose the Action Adventure.
                        if ($Action -ieq "Start")
                        {
                            # Start the service.  No data is returned.
                            $_invokeResponse = Invoke-Command -Session $session -ScriptBlock {
                                param($ServiceName)
                                Write-Output ("Starting ({0}) on ({1}) as ({2})" -f $ServiceName, $(HOSTNAME.EXE), $(whoami.exe))
                                Start-Service -Name $ServiceName 2>&1
                            } -ArgumentList $_targetService.ServiceName
                        }
                        elseif ($Action -ieq "Stop")
                        {
                            # Stop the service.  No data is returned.
                            $_invokeResponse = Invoke-Command -Session $session -ScriptBlock {
                                param($ServiceName)
                                Write-Output ("Stopping ({0}) on ({1}) as ({2})" -f $ServiceName, $(HOSTNAME.EXE), $(whoami.exe))
                                Stop-Service -Name $ServiceName 2>&1
                            } -ArgumentList $_targetService.ServiceName
                        }
                        elseif ($Action -ieq "ReStart")
                        {
                            # Restart the service.  No data is returned.
                            $_invokeResponse = Invoke-Command -Session $session -ScriptBlock {
                                param($ServiceName)
                                Write-Output ("Restarting ({0}) on ({1}) as ({2})" -f $ServiceName, $(HOSTNAME.EXE), $(whoami.exe))
                                Restart-Service -Name $ServiceName 2>&1
                            } -ArgumentList $_targetService.ServiceName
                        }
                        elseif ($Action -ieq "Update")
                        {
                            #Set the service Credential.
                            $serviceCredential = ($ServiceCreds[$_targetService.ServiceCred])
                            $_invokeResponse = Invoke-Command -Session $session -ScriptBlock {
                                param($ServiceName, [pscredential]$ServiceUser)
                                Write-Output ("Updating ({0}) on ({1}) as ({2}) : Updating Run User to ({3})" -f $ServiceName, $(HOSTNAME.EXE), $(whoami.exe), $ServiceUser.Username)
                                Set-Service -Name $ServiceName -Credential $ServiceUser 2>&1
                            } -ArgumentList $_targetService.ServiceName, $serviceCredential
                        }
                        elseif ($Action -ieq "Disable")
                        {
                            #Set the service startup type.
                            $_invokeResponse = Invoke-Command -Session $session -ScriptBlock {
                                param($ServiceName)
                                Write-Output ("Setting startup to Disabled ({0}) on ({1}) as ({2})" -f $ServiceName, $(HOSTNAME.EXE), $(whoami.exe))
                                Set-Service -Name $ServiceName -StartupType Disabled 2>&1
                            } -ArgumentList $_targetService.ServiceName
                        }
                        elseif ($Action -ieq "Automatic")
                        {
                            #Set the service startup type.
                            $_invokeResponse = Invoke-Command -Session $session -ScriptBlock {
                                param($ServiceName)
                                Write-Output ("Setting startup to Automatic ({0}) on ({1}) as ({2})" -f $ServiceName, $(HOSTNAME.EXE), $(whoami.exe))
                                Set-Service -Name $ServiceName -StartupType Automatic 2>&1
                            } -ArgumentList $_targetService.ServiceName
                        }
                        elseif ($Action -ieq "Delayed")
                        {
                            #Set the service startup type.
                            $_invokeResponse = Invoke-Command -Session $session -ScriptBlock {
                                param($ServiceName)
                                Write-Output ("Setting startup to Delayed ({0}) on ({1}) as ({2})" -f $ServiceName, $(HOSTNAME.EXE), $(whoami.exe))
                                Set-Service -Name $ServiceName -StartupType AutomaticDelayedStart 2>&1
                            } -ArgumentList $_targetService.ServiceName
                        }
                        elseif ($Action -ieq "Manual")
                        {
                            #Set the service startup type.
                            $_invokeResponse = Invoke-Command -Session $session -ScriptBlock {
                                param($ServiceName)
                                Write-Output ("Setting startup to Manual ({0}) on ({1}) as ({2})" -f $ServiceName, $(HOSTNAME.EXE), $(whoami.exe))
                                Set-Service -Name $ServiceName -StartupType Manual 2>&1
                            } -ArgumentList $_targetService.ServiceName
                        }
                        elseif ($Action -ieq "Status")
                        {
                            #Get the current status.
                            $_invokeResponse = Invoke-Command -Session $session -ScriptBlock {
                                param($ServiceName)
                                Write-Output ("Getting status of ({0}) on ({1}) as ({2})" -f $ServiceName, $(HOSTNAME.EXE), $(whoami.exe))
                                (Get-Service -Name $ServiceName).Status 2>&1
                            } -ArgumentList $_targetService.ServiceName
                        }

                        # Capture the error
                        $_invokeError = $Error

                        # Output to the log.
                        $Logger.Write(("{0,24} | Action ({1, 10}) | Service ({2}) | ({3}) | Response`r`n(`r`n`t{4}`r`n)" -f 
                        $_targetService.Hostname, $Action, $_targetService.ServiceName, "Submitted", ($_invokeResponse -join "`r`n`t")), "Information")

                        # Set the timeout time.
                        $_moveOnTime = (Get-Date).AddSeconds($_targetService.TimeOut)

                        # Create the post status variable.
                        $postStatus = ""

                        # Clear the error variable.
                        $Error.Clear()

                        # Wait for the status change
                        do
                        {
                            # Get the current status of the service.
                            $postStatus = (Invoke-Command -Session $session -ScriptBlock { 
                                param($ServiceName)
                                Write-Output ("Getting status of ({0}) on ({1}) as ({2})" -f $ServiceName, $(HOSTNAME.EXE), $(whoami.exe))
                                (Get-Service -Name $ServiceName).Status 2>&1
                            } -ArgumentList $_targetService.ServiceName)

                            $_curStatus = ""
                            
                            # Check if the Post Status is an object array.
                            if ($postStatus.GetType() -eq [System.Object[]])
                            {
                                # Assign the Get-Service result to the current status.
                                $_curStatus = $postStatus[1].ToString()
                            }
                            else
                            {
                                # Assign the result to the current status.
                                $_curStatus = $postStatus.ToString()
                            }

                            # Sleep
                            Start-Sleep -Seconds 5
                        }
                        while ((-not ($serviceStates.Contains($_curStatus)) -and ((Get-Date) -le $_moveOnTime) -and (-not ($Error)) -and (-not ($_curStatus -ilike "Cannot find any service with service name*"))))

                        $Logger.Write(("{0,24} | Action ({1, 10}) | Service ({2}) | Post Status `r`n(`r`n`t{3}`r`n)" -f 
                        $_targetService.Hostname, $Action, $_targetService.ServiceName, ($postStatus -join "`r`n`t")), "Debug")

                        # Check Invoke Error
                        if ($_invokeError)
                        {
                            $Logger.Write(("Host ({0}) | Service ({1}) | Action ({2}) | Error `r`n(`r`n`t{3}`r`n)" -f
                            $_targetService.Hostname, $_targetService.ServiceName, $Action, $($_invokeError -join "`r`n`t")), "Error")
                        }
                    }

                    # Close the session
                    $session | Remove-PSSession
                }
                else
                {
                    $Logger.Write(("Failed to open session!  Skipping Host!"), "Error")
                }
                
            }
        }
        else
        {
            # No Target Services specified.
            $Logger.Write(("No Target Services Provided!"), "Error")
            exit 404
        }

    }

}

function Set-ServicePropertiesThreaded
{
    <#
        .DESCRIPTION
        This function will loop over the Targeted Services and set the requested action on the
        Windows service account.

        .PARAMETER MaxThreads
        [int]   If 0 no sub / job threads will be created.  This is split on the Hostname.
                If greater than 0 then the number of background threads will be created.

        .PARAMETER Action
        [string]    The action to be performed on the service.

        .PARAMETER AdminCreds
        [hashtable] A hashtable containing the credentials needed to authenticate to the target server.

        .PARAMETER ServiceCreds
        [hashtable] A hashtable containing the credentials needed to run the target service.

        .PARAMETER TargetServices
        [hashtable] A hashtable containing the Host information and the Services to perform the
                    requested action on.
    #>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false
            )]
        [int] $MaxThreads,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false
            )]
            [ValidateSet("Start", "Stop", "ReStart", "Update", "Disable", "Automatic", "Delayed", "Manual", "Status")]
        [string] $Action,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false
            )]
        [hashtable] $AdminCreds,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false
            )]
        [hashtable] $ServiceCreds,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false
            )]
        [object[]] $TargetServices
    )
    # This function will multi thread the service management operations.
    # https://learn.microsoft.com/en-us/powershell/scripting/learn/deep-dives/write-progress-across-multiple-threads?view=powershell-7.4
    
    # Build the default objects.
    $_jobs = New-Object System.Collections.Generic.List[hashtable] # This will hold the jobs to be processed.
    $_uniqueHostsAdmins = @{} # This will hold the Unique Host Names and Admin IDs.
    $_uniqueServiceIDs = @{}  # This will hold the Service information and Service IDs.

    # Check if the Target Services were provided.
    if (($null -ne $TargetServices) -and ($TargetServices.Count -gt 0))
    {
        # At least 1 target service provided.  Build the unique targets.
        #  Get the unique host entries and the administrative ID names.  AdminSafe, AdminUser, AdminAddress
        $_uniqueHostsAdmins = $TargetServices | Sort-Object Hostname -Unique | Select-Object Hostname, HostFqdn, HostIP, @{Name="AdminCred"; Expression={$($_.AdminSafe) + "/" + $($_.AdminUser) + "/" + $($_.AdminAddress)}}, TimeOut

        # Get the unique Host and Service entries with the service ID names. ServiceSafe,ServiceUser,ServiceAddress -Unique
        $_uniqueServiceIDs = $TargetServices | Sort-Object Hostname, ServiceName -Unique | Select-Object Hostname, HostFqdn, HostIP, ServiceName, TimeOut, @{Name="ServiceCred"; Expression={$($_.ServiceSafe) + "/" + $($_.ServiceUser) + "/" + $($_.ServiceAddress)}}
    }

    # Build the Job Origin Table after checking that there are host IDs.
    if (($null -ne $_uniqueHostsAdmins) -and ($_uniqueHostsAdmins.Count -gt 0))
    {
        # Create an ID variable that is incremented.
        $_id = 0

        # Loop over the unique hosts and get the services.
        foreach ($uh in $_uniqueHostsAdmins)
        {
            # Increment the ID variable.
            $_id++

            # Get all services for this host.
            $_targetedServices = $_uniqueServiceIDs | Where-Object Hostname -ieq $uh.Hostname

            # Create a null Service Credential.
            $_serviceCreds = @{}

            # Check if the Service Credentials were provided.
            if (($null -ne $ServiceCreds) -and ($ServiceCreds.Count -gt 0))
            {
                # Service Credentials were provided.
                # Get the unique Service Credential Names.
                $_credNames = $_targetedServices | Sort-Object ServiceCred -Unique | Select-Object ServiceCred

                # Get all of the Service Credentials required
                foreach ($_scn in $_credNames)
                {
                    # Add the credential
                    $_serviceCreds.Add($_scn, $ServiceCreds[$_scn])
                }
            }

            # Add the data to the jobs array.
            $_jobs.Add(@{
                Id = $_id                       # This is the unique identifier for the job.
                Hostname = $uh.Hostname         # This is the hostname for the job.
                HostFqdn = $uh.HostFqdn         # This is the Hosts Fully Qualified Domain Name.
                HostIP = $uh.HostIP             # This is the Host's IP address.
                Timeout = $uh.TimeOut           # This is the TimeOut for making the host connection.
                ServiceCreds = $_serviceCreds   # This is the credentials needed for the Windows Services.
                AdminCred = $AdminCreds[$uh.AdminCred] # This is the administrative credential needed to connect to the host.
                Services = $_targetedServices   # This is a list of the services and service account credentials needed.
                Action = $Action                # This is the action to be performed on the Windows Service.
            })
        }
    }

    # Test the jobs.
    if ($_jobs.Count -gt 0)
    {
        # There is at least 1 job.
        $Logger.Write(("Jobs Created. Count:  {0}" -f $_jobs.Count), "Information")

        # Create a hashtable for the process.
        $origin = @{}

        # Populate the origin table with the IDs from the Jobs table.
        $_jobs | Foreach-Object {$origin.($_.Id) = @{}}

        # Create synced hashtable
        $sync = [System.Collections.Hashtable]::Synchronized($origin)

        # Status
        $Logger.Write(("Submitting Jobs."), "Information")

        # Call the for each object to start the parallel jobs.
        $_job = $_jobs | ForEach-Object -ThrottleLimit $MaxThreads -AsJob -Parallel {
            # Create a copy of the synched hash table.
            $syncCopy = $using:sync

            # Create a list of Service Status States.
            $serviceStates = @("Paused", "Running", "Stopped")

            # Create the Process in the synched hash table.
            $process = $syncCopy.$($PSItem.Id)

            # Set the process ID.
            $process.Id = $PSItem.Id

            # Set the process Name.
            $process.Name = $PSItem.Hostname

            # Set the current process activity.
            $process.Activity = "Starting $($PSItem.Id)"

            # Set the current process status.
            $process.Status = "Connecting"

            # Make the connection to the host.
            #  Clear the error variable.
            $Error.Clear()

            # Create a blank session.
            $session = $null

            # Check for an existing PowerShell session.  Filter on the host's FQDN and the state.
            $_hostPSVSessions = (Get-PSSession -ComputerName $PSItem.HostFqdn -ErrorAction SilentlyContinue) | Where-Object {($_.ConfigurationName -like "PowerShell.7*")}
            $_hostPSASessions = ($_hostPSVSessions) | Where-Object {($_.State -eq "Opened")}
            $_availSessions = $_hostPSASessions | Where-Object Availability -eq Available

            # Test the results.
            if ($_availSessions.Count -gt 0)
            {
                # Output startup message.
                $process.History = ("{0} | {1:d8} | {2,24} | Re-Use Existing Connection ({3}).`r`n" -f 
                (Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $PSItem.Id, $PSItem.Hostname, $PSItem.HostFqdn)

                # Re-use a session
                $session = $_availSessions[0]
            }
            else
            {
                # Output startup message.
                $process.History = ("{0} | {1:d8} | {2,24} | Connecting to host ({3}).`r`n" -f 
                (Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $PSItem.Id, $PSItem.Hostname, $PSItem.HostFqdn)
                
                # Create the session.
                $session = New-PSSession -ComputerName $PSItem.HostFqdn -Credential $PSItem.AdminCred -ErrorAction SilentlyContinue -ConfigurationName PowerShell.7
            }
            
            # Test the result of the new session.
            if ($Error)
            {
                # Failed.  A new PS Session was NOT created.
                # Set the current process status.
                $process.Status = "Failed"

                # Process. update activity
                $process.Activity = "Failed $($PSItem.id)"

                # Output to the log.
                $process.History += ("{0} | {1:d8} | {2,24} | Connection FAILED to host ({3}).`r`n" -f 
                (Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $PSItem.Id, $PSItem.Hostname, $PSItem.HostFqdn)
            }
            else
            {
                # Success.
                # Set the current process status.
                $process.Status = "Connected"

                # Process. update activity
                $process.Activity = "Running $($PSItem.id)"
                
                # Set the loop counts.
                $_loopSize = $PSItem.Services.Count
                $_loopPos = 0

                # Loop over the targeted services.
                foreach ($service in $PSItem.Services)
                {
                    # Update the loop position.
                    $_loopPos++

                    # Update process on status.
                    $process.Status = "$($PSItem.Hostname) : $($service.ServiceName)"
                    $process.PercentComplete = (($_loopPos / $_loopSize) * 100)

                    # Clear the error variable.
                    $Error.Clear()

                    # Get the current status of the service.
                    $initialStatus = (Invoke-Command -Session $session -ScriptBlock { 
                        param($ServiceName)
                        Write-Output ("Getting status of ({0}) on ({1}) as ({2})" -f $ServiceName, $(HOSTNAME.EXE), $(whoami.exe))
                        (Get-Service -Name $ServiceName).Status 2>&1
                    } -ArgumentList $service.ServiceName)

                    # Output to the log.
                    $process.History += ("{0} | {1:d8} | {2,24} | Action ({3, 10}) | Service ({4}) | Initial Status `r`n(`r`n`t{5}`r`n).`r`n" -f 
                    (Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $PSItem.Id, $PSItem.Hostname,
                    $PSItem.Action, $service.ServiceName, ($initialStatus -join "`r`n`t"))

                    # Invoke Response Variable. Most of the calls do not give a response.
                    $_invokeResponse = $null

                    # Choose the Action Adventure.
                    if ($PSItem.Action -ieq "Start")
                    {
                        # Start the service.  No data is returned.
                        $_invokeResponse = Invoke-Command -Session $session -ScriptBlock {
                            param($ServiceName)
                            Write-Output ("Starting service ({0}) on ({1}) as ({2})" -f $ServiceName, $(HOSTNAME.EXE), $(whoami.exe))
                            Start-Service -Name $ServiceName 2>&1
                        } -ArgumentList $service.ServiceName
                    }
                    elseif ($PSItem.Action -ieq "Stop")
                    {
                        # Stop the service.  No data is returned.
                        $_invokeResponse = Invoke-Command -Session $session -ScriptBlock {
                            param($ServiceName)
                            Write-Output ("Stopping service ({0}) on ({1}) as ({2})" -f $ServiceName, $(HOSTNAME.EXE), $(whoami.exe))
                            Stop-Service -Name $ServiceName 2>&1
                        } -ArgumentList $service.ServiceName
                    }
                    elseif ($PSItem.Action -ieq "ReStart")
                    {
                        # Restart the service.  No data is returned.
                        $_invokeResponse = Invoke-Command -Session $session -ScriptBlock {
                            param($ServiceName)
                            Write-Output ("Restarting service ({0}) on ({1}) as ({2})" -f $ServiceName, $(HOSTNAME.EXE), $(whoami.exe))
                            Restart-Service -Name $ServiceName 2>&1
                        } -ArgumentList $service.ServiceName
                    }
                    elseif ($PSItem.Action -ieq "Update")
                    {
                        #Set the service Credential.
                        $_invokeResponse = Invoke-Command -Session $session -ScriptBlock {
                            param($ServiceName, [pscredential]$ServiceUser)
                            Write-Output ("Updating service credential ({0}) on ({1}) as ({2}) : Updating Run User to ({3})" -f $ServiceName, $(HOSTNAME.EXE), $(whoami.exe), $ServiceUser.Username)
                            Set-Service -Name $ServiceName -Credential $ServiceUser 2>&1
                        } -ArgumentList $service.ServiceName, $PSItem.ServiceCreds[$service.ServiceCred]
                    }
                    elseif ($PSItem.Action -ieq "Disable")
                    {
                        #Set the service startup type.
                        $_invokeResponse = Invoke-Command -Session $session -ScriptBlock {
                            param($ServiceName)
                            Write-Output ("Setting startup to Disabled ({0}) on ({1}) as ({2})" -f $ServiceName, $(HOSTNAME.EXE), $(whoami.exe))
                            Set-Service -Name $ServiceName -StartupType Disabled 2>&1
                        } -ArgumentList $service.ServiceName
                    }
                    elseif ($PSItem.Action -ieq "Automatic")
                    {
                        #Set the service startup type.
                        $_invokeResponse = Invoke-Command -Session $session -ScriptBlock {
                            param($ServiceName)
                            Write-Output ("Setting startup to Automatic ({0}) on ({1}) as ({2})" -f $ServiceName, $(HOSTNAME.EXE), $(whoami.exe))
                            Set-Service -Name $ServiceName -StartupType Automatic 2>&1
                        } -ArgumentList $service.ServiceName
                    }
                    elseif ($PSItem.Action -ieq "Delayed")
                    {
                        #Set the service startup type.
                        $_invokeResponse = Invoke-Command -Session $session -ScriptBlock {
                            param($ServiceName)
                            Write-Output ("Setting startup to Delayed ({0}) on ({1}) as ({2})" -f $ServiceName, $(HOSTNAME.EXE), $(whoami.exe))
                            Set-Service -Name $ServiceName -StartupType AutomaticDelayedStart 2>&1
                        } -ArgumentList $service.ServiceName
                    }
                    elseif ($PSItem.Action -ieq "Manual")
                    {
                        #Set the service startup type.
                        $_invokeResponse = Invoke-Command -Session $session -ScriptBlock {
                            param($ServiceName)
                            Write-Output ("Setting startup to Manual ({0}) on ({1}) as ({2})" -f $ServiceName, $(HOSTNAME.EXE), $(whoami.exe))
                            Set-Service -Name $ServiceName -StartupType Manual 2>&1
                        } -ArgumentList $service.ServiceName
                    }
                    elseif ($PSItem.Action -ieq "Status")
                    {
                        #Set the service startup type.
                        $_invokeResponse = Invoke-Command -Session $session -ScriptBlock {
                            param($ServiceName)
                            Write-Output ("Getting status of ({0}) on ({1}) as ({2})" -f $ServiceName, $(HOSTNAME.EXE), $(whoami.exe))
                            (Get-Service -Name $ServiceName).Status 2>&1
                        } -ArgumentList $service.ServiceName
                    }

                    # Capture the error
                    $_invokeError = $Error

                    # Output to the log.
                    $process.History += ("{0} | {1:d8} | {2,24} | Action ({3, 10}) | Service ({4}) | Submitted | Response `r`n(`r`n`t{5}`r`n).`r`n" -f 
                    (Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $PSItem.Id, $PSItem.Hostname,
                    $PSItem.Action, $service.ServiceName, ($_invokeResponse -join "`r`n`t"))

                    # Set the timeout time.
                    $_moveOnTime = (Get-Date).AddSeconds($PSItem.TimeOut)

                    # Create the post status variable.
                    $postStatus = ""

                    # Wait for the status change
                    do
                    {
                        # Get the current status of the service.
                        $postStatus = (Invoke-Command -Session $session -ScriptBlock { 
                            param($ServiceName)
                            Write-Output ("Getting status of ({0}) on ({1}) as ({2})" -f $ServiceName, $(HOSTNAME.EXE), $(whoami.exe))
                            (Get-Service -Name $ServiceName).Status 2>&1
                         } -ArgumentList $service.ServiceName)

                        $_curStatus = ""
                        
                        # Check if the Post Status is an object array.
                        if ($postStatus.GetType() -eq [System.Object[]])
                        {
                            # Assign the Get-Service result to the current status.
                            $_curStatus = $postStatus[1].ToString()
                        }
                        else
                        {
                            # Assign the result to the current status.
                            $_curStatus = $postStatus.ToString()
                        }

                        # Sleep
                        Start-Sleep -Seconds 5
                    }
                    while ((-not ($serviceStates.Contains($_curStatus)) -and ((Get-Date) -le $_moveOnTime) -and (-not ($Error)) -and (-not ($_curStatus -ilike "Cannot find any service with service name*"))))
                    
                    # Output to the log.
                    $process.History += ("{0} | {1:d8} | {2,24} | Action ({3, 10}) | Service ({4}) | Post Status `r`n(`r`n`t{5}`r`n)`r`n`r`n" -f 
                    (Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $PSItem.Id, $PSItem.Hostname,
                    $PSItem.Action, $service.ServiceName, ($postStatus -join "`r`n`t"))

                    # Add the Invoke Response to the job data.
                    $process.InvokeResponse += $_invokeResponse

                    # Add the Invoke Error to the job data.
                    $process.InvokeError += $_invokeError

                    # Check Invoke Error
                    if ($_invokeError)
                    {
                        $process.History += ("{0} | {1:d8} | {2,24} | Action ({3, 10}) | Service ({4}) | Error ({5})" -f
                        (Get-Date -Format "yyyy-MM-dd hh:mm:ss"), $PSItem.Id, $PSItem.Hostname, 
                        $PSItem.Action, $service.ServiceName, $_invokeError)
                    }
                }

                # Set the current process status.
                $process.Status = "Finished"
                $process.PercentComplete = 100

                # Process. update activity
                $process.Activity = "Id $($PSItem.id) Finished"

                # Close the session
                $session | Remove-PSSession
            }

            # Mark process as completed
            $process.Completed = $true
        }

        # Status
        $Logger.Write(("Submitted Jobs.  Waiting for result."), "Information")

        # Watch the jobs running.
        while($_job.State -eq 'Running')
        {
            $sync.Keys | Foreach-Object {
                # If key is not defined, ignore
                if(![string]::IsNullOrEmpty($sync.$_.keys))
                {
                    # Create parameter hashtable to splat and strip invalid parameters.
                    $param = $sync.$_ | Select-Object Activity, Status, Id, PercentComplete, SecondsRemaining, CurrentOperation, ParentId, Completed, SourceId

                    # Execute Write-Progress
                    Write-Progress @param 
                }
            }

            # Wait to refresh to not overload gui
            Start-Sleep -Seconds 0.1
        }

        # Status
        $Logger.Write(("Jobs have Completed."), "Information")

        # Get the results.
        $_results = $_job | Receive-Job

        # Loop over the job queue.
        foreach ($job in $sync.Keys)
        {
            # Get details.
            $jobDetails = $sync[$job]

            # Status
            $Logger.Write(("Job ({0}) Name ({1}) Started at ({2}) | Job History Below" -f $jobDetails.Id, $jobDetails.Name, $jobDetails.PSBeginTime), "Information")
            $Logger.Write($jobDetails.History, "Information", "Both", $true)
            $Logger.Write(("End of Job History."), "Information")
        }

        # Loop over the job results.
        foreach ($result in $_results)
        {
            # Status
            $Logger.Write(("Job Results."), "Information")
        }
    }
    else
    {
        $Logger.Write(("No Jobs Created! Count:  {0}" -f $_jobs.Count), "Error")
        $Logger.Write(("    Max Threads  :  {0}" -f $MaxThreads), "Error")
        $Logger.Write(("Requested Action :  {0}" -f $Action), "Error")
        $Logger.Write(("    Admin Creds #:  {0}" -f $AdminCreds.Count), "Error")
        $Logger.Write(("  Service Creds #:  {0}" -f $ServiceCreds.Count), "Error")
        $Logger.Write(("Target Services #:  {0}" -f $TargetServices.Count), "Error")
        exit 404
    }
    
}
#endRegion Windows Server Functions
########################################
########################################
#region CSV Functions
########################################
#endRegion CSV Functions
########################################
########################################
#region Config Functions
########################################
function Get-Configuration
{
    param(
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false
            )]
        [string] $Path
    )
    
    # Test the path.
    if (($null -ne $Path) -and ($Path -ne ""))
    {
        # The path is not null or blank.
        if (Test-Path -Path $Path)
        {
            # The file exists.  Get the file details.
            $_fileDetails = Get-Item -Path $Path
            if ($_fileDetails.Extension -ieq ".psd1")
            {
                # The file has the correct extension.
                if ($_fileDetails.Length -gt 0)
                {
                    # The file is not empty.
                    return Import-PowerShellDataFile -Path $Path
                }
                else
                {
                    Write-Warning ("Path provided:  {0}" -f $Path)
                    Write-Error ("The provided file is EMPTY!`r`n`tSize:  {0}" -f $_fileDetails.Length)
                    exit
                }
            }
            else
            {
                Write-Warning ("Path provided:  {0}" -f $Path)
                Write-Error ("The provided file has an incorrect file extension!`r`n`tExtension:  {0}" -f $_fileDetails.Extension)
                exit
            }
        }
        else
        {
            Write-Error ("The provided path does NOT exist!`r`n`tGiven:  {0}" -f $Path)
            exit
        }
    }
    else
    {
        Write-Error ("The provided path is either NULL or BLANK!`r`n`tGiven:  {0}" -f $Path)
        exit
    }
}

function Update-CommandLineParameter
{
    # If the command line parameter was specified it should override the configuration file.
    if ($PSBoundParameters.Keys.Contains("LogLevel"))
    {
        $script:_scriptConfig["Logging"]["Level"] = $LogLevel
    }
    if ($PSBoundParameters.Keys.Contains("LogFolder"))
    {
        $script:_scriptConfig["Logging"]["Folder"] = $LogFolder
    }
    if ($PSBoundParameters.Keys.Contains("LogFile"))
    {
        $script:_scriptConfig["Logging"]["Filename"] = $LogFile
    }
    if ($PSBoundParameters.Keys.Contains("InputFiles"))
    {
        $script:_scriptConfig["Inputs"]["InputFiles"] = $InputFiles
    }
    if ($PSBoundParameters.Keys.Contains("OutFile"))
    {
        $script:_scriptConfig["Inputs"]["OutFile"] = $OutFile
    }
    if ($PSBoundParameters.Keys.Contains("ThumbPrint"))
    {
        $script:_scriptConfig["Inputs"]["ThumbPrint"] = $ThumbPrint
    }
    if ($PSBoundParameters.Keys.Contains("AllowCPMDisabled"))
    {
        $script:_scriptConfig["Inputs"]["AllowCPMDisabled"] = $AllowCPMDisabled
    }
    if ($PSBoundParameters.Keys.Contains("MaxCPMWait"))
    {
        $script:_scriptConfig["Inputs"]["MaxCPMWait"] = $MaxCPMWait
    }
    if ($PSBoundParameters.Keys.Contains("Reason"))
    {
        $script:_scriptConfig["Inputs"]["Reason"] = $Reason
    }
    if ($PSBoundParameters.Keys.Contains("RotateServicePassword"))
    {
        $script:_scriptConfig["Inputs"]["RotateServicePassword"] = $RotateServicePassword
    }

    # Update the log folder to be a fully qualified path.
    if (($null -eq $script:_scriptConfig["Logging"]["Folder"]) -or ($script:_scriptConfig["Logging"]["Folder"] -eq ""))
    {
        # The folder is blank.  Set it to the current folder.
        $script:_scriptConfig["Logging"]["Folder"] = Get-Location.Path
    }
    elseif (($null -ne $script:_scriptConfig["Logging"]["Folder"]) -and ($script:_scriptConfig["Logging"]["Folder"] -ne ""))
    {
        # The folder is not blank.
        # Test / Create the Logs folder
        Write-Verbose ("Test if folder exists!  Folder:  {0}" -f $script:_scriptConfig["Logging"]["Folder"])
        if (!(Test-Path -Path $script:_scriptConfig["Logging"]["Folder"]))
        {
            # The folder does not exist.  Create it.
            Write-Verbose ("Creating Folder:  {0}" -f $script:_scriptConfig["Logging"]["Folder"])
            $null = New-Item -Path $script:_scriptConfig["Logging"]["Folder"] -ItemType Directory
        }
        else
        {
            Write-Verbose ("Folder Exists!  Folder:  {0}" -f $script:_scriptConfig["Logging"]["Folder"])
        }

        #Get the fully qualified path.
        $script:_scriptConfig["Logging"]["Folder"] = (Get-Item -Path $script:_scriptConfig["Logging"]["Folder"]).FullName
    }
}
#endRegion Config Functions
########################################
########################################
#region Help
########################################
function Get-Help
{
    # This function will print out the help information.
    Get-Help $MyInvocation.MyCommand.Definition -Full
    exit
}
#endRegion Help
########################################
########################################
#region Proccess Command Line Parameters
########################################
# The following hash table is just like the configuration file.  Minus the $script:_scriptConfig=
# The values in this section SHOULD NOT be modified.  Use the configuration file.
# Create a variable to hold the configuration data.
$script:_scriptConfig = @{
    # This section holds the information needed to access the CyberArk Password Vault Web Access server.
    CyberArk_PVWA = @{
        # This is HTTP or HTTPS
        HTTP_Scheme = "https"

        # This is the IP, Short Name, or Fully Qualified Domain Name
        Address = "epv.company.com"

        # This is the TCP Port that the web server is listening on.  Default 443
        Port = 443

        # This is the IIS Application name.  Default PasswordVault
        IIS_Application = "PasswordVault"

        # This is needed if using the IP address or a Self Signed certificate on the PVWA.
        IgnoreSSLErrors = $false

        # This is the type of authentication to use when authenticating to the PVWA.
        # Valid values:  "CyberArk", "LDAP", "SAML", "PKI", "PKIPN"
        User_Authentication = "CyberArk"
    }

    # This section holds the information needed for logging.
    Logging = @{
        # This is the logging level.
        # Valid values:  Force", "None", "Critical", "Error", "Warning", "Information", "Debug", "Verbose", "Trace"
        Level = $LogLevel

        # Log Folder.  If blank, the current folder is used.  Can be Relative or Fully Qualified.
        Folder = $LogFolder

        # Log Filename.  If blank, a default will be used.
        Filename = $LogFile
    }

    # This section holds the inputs information.
    Inputs = @{
        # This is one or more files to be processed.
        InputFiles = $InputFiles

        # This is a single output file to write the results to.
        OutFile = $OutFile

        # This is the Thumbprint of the x509 Client Authentication certificate to be used.
        ThumbPrint = $ThumbPrint

        # All CPM Disabled accounts to be considered successfull if True.
        AllowCPMDisabled = $true

        # Maximum CPM Wait time in minutes.  How long should the script wait for the CPM change process.
        MaxCPMWait = 1

        # Account checkout reason.
        Reason = "Change Number"

        # Unlock accounts that are locked.
        Unlock = $true

        # Rotate Service Account Password
        RotateServicePassword = $true
    }

    # This section holds the information about the number of threads to run.
    Threads = @{
        # Total number of background threads allowed to run.
        Max = 3


    }
}
#endRegion Proccess Command Line Parameters
########################################
########################################
#region Flow
########################################
########################################
    #region Configuration Loading
########################################
# Verbose output with the script variables and their values.
Write-Verbose ("******************** Script Variables ********************")
Write-Verbose ("ConfigFile:  {0}" -f $ConfigFile)
Write-Verbose ("InputFiles:`r`n`t{0}" -f ($script:_scriptConfig["Inputs"]["InputFiles"] -join "`r`n`t"))
Write-Verbose ("LogLevel  :  {0}" -f $script:_scriptConfig["Logging"]["Level"])
Write-Verbose ("LogFolder :  {0}" -f $script:_scriptConfig["Logging"]["Folder"])
Write-Verbose (" LogFile  :  {0}" -f $script:_scriptConfig["Logging"]["FileName"])
Write-Verbose (" OutFile  :  {0}" -f $script:_scriptConfig["Inputs"]["OutFile"])
Write-Verbose ("ThumbPrint:  {0}" -f $script:_scriptConfig["Inputs"]["ThumbPrint"])
Write-Verbose ("MaxCPMWait:  {0}" -f $script:_scriptConfig["Inputs"]["MaxCPMWait"])
Write-Verbose ("  Reason  :  {0}" -f $script:_scriptConfig["Inputs"]["Reason"])
Write-Verbose ("  Unlock  :  {0}" -f $script:_scriptConfig["Inputs"]["Unlock"])
Write-Verbose ("AllowCPMDisabled:  {0}" -f $script:_scriptConfig["Inputs"]["AllowCPMDisabled"])
Write-Verbose ("RotateServicePassword:  {0}" -f $script:_scriptConfig["Inputs"]["RotateServicePassword"])
Write-Verbose ("******************** Script Variables ********************")

# Check if a configuration file was specified.
if (($null -ne $ConfigFile) -and ($ConfigFile -ne ""))
{
    # The file path is not null or blank. 
    Write-Host ("Reading Configuration.`r`n`tFile:  {0}" -f $ConfigFile)

    # Read the configuration.
    $script:_scriptConfig = Get-Configuration -Path $ConfigFile

    # Make sure any commandline variable was not over written.
    Update-CommandLineParameter
}
else
{
    # Warning
    Write-Warning ("No configuration file specified!`r`n`tGiven:  {0}" -f $ConfigFile)

    # Create a variable to hold the fully qualified path to the configuration folder.
    $_confFullPath = ""

    # Test / Create the Conf folder
    Write-Verbose ("Test if folder exists!`r`n`tFolder:  {0}" -f $_configPath)

    # Test if the folder exists.  If not, create it.
    if (!(Test-Path -Path $_configPath))
    {
        # The folder does not exist.  Create it.
        $null = New-Item -Path $_configPath -ItemType Directory

        # Get the fully qualified path from the relative path.
        $_confFullPath = (Get-Item -Path $_configPath).FullName

        Write-Verbose ("Created Folder:`r`n`tFolder:  {0}" -f $_confFullPath)
        
    }
    else
    {
        # Get the fully qualified path from the relative path.
        $_confFullPath = (Get-Item -Path $_configPath).FullName
        
        Write-Verbose ("Folder Exists!`r`n`tFolder:  {0}" -f $_confFullPath)
    }

    # Check if the default configuration file exists.
    Write-Verbose ("Checking Default Configuration file.`r`n`tFileName:  {0}" -f $_configFileName)
    
    # Join the fully qualified configuration folder path with the configuration filename.
    $_confFileFullPath = Join-Path -Path $_confFullPath -ChildPath $_configFileName

    # Test if the file exists.  If not, create it.
    if (!(Test-Path -Path $_confFileFullPath))
    {
        # The folder does not exist.  Create it.
        Write-Host ("Creating File:  {0}" -f $_confFileFullPath)
        $null = New-Item -Path $_confFileFullPath -ItemType File

        try
        {
            #
            # Write the default configuration to the file.
            $_defaultConfigString = ConvertTo-Psd -InputObject $script:_scriptConfig

            # Write to the file.
            Out-File -FilePath $_confFileFullPath -Force -InputObject $_defaultConfigString

            # Status
            Write-Warning ("Default Configuration file created!`r`n`tHere:  {0}" -f $_confFileFullPath)
        }
        catch
        {
            throw $_
        }
    }
    else
    {
        Write-Verbose ("File Exists!`r`n`tFile:  {0}" -f $_confFileFullPath)
    }

    
    exit 404
}

# Verbose output with the script variables and their values.
Write-Verbose ("******************** New Script Variables ********************")
Write-Verbose ("InputFiles :`r`n`t{0}" -f ($script:_scriptConfig["Inputs"]["InputFiles"] -join "`r`n`t"))
Write-Verbose (" LogLevel  :  {0}" -f $script:_scriptConfig["Logging"]["Level"])
Write-Verbose ("LogFolder  :  {0}" -f $script:_scriptConfig["Logging"]["Folder"])
Write-Verbose ("  LogFile  :  {0}" -f $script:_scriptConfig["Logging"]["FileName"])
Write-Verbose ("  OutFile  :  {0}" -f $script:_scriptConfig["Inputs"]["OutFile"])
Write-Verbose ("ThumbPrint :  {0}" -f $script:_scriptConfig["Inputs"]["ThumbPrint"])
Write-Verbose ("MaxCPMWait :  {0}" -f $script:_scriptConfig["Inputs"]["MaxCPMWait"])
Write-Verbose ("   Reason  :  {0}" -f $script:_scriptConfig["Inputs"]["Reason"])
Write-Verbose ("   Unlock  :  {0}" -f $script:_scriptConfig["Inputs"]["Unlock"])
Write-Verbose ("Max Threads:  {0}" -f $script:_scriptConfig["Threads"]["Max"])
Write-Verbose ("AllowCPMDisabled:  {0}" -f $script:_scriptConfig["Inputs"]["AllowCPMDisabled"])
Write-Verbose ("RotateServicePassword:  {0}" -f $script:_scriptConfig["Inputs"]["RotateServicePassword"])
Write-Verbose ("******************** New Script Variables ********************")
#endRegion Configuration Loading
########################################
# Setup logging.
$Logger = [Logger]::new($script:_scriptConfig["Logging"]["Level"], $script:_scriptConfig["Logging"]["FileName"], $script:_scriptConfig["Logging"]["Folder"])

# Starting message
$Logger.Write("**************************************************", "Information")
$Logger.Write("******************** Starting ********************", "Force")
$Logger.Write("**************************************************", "Information")

# Output the log file path.
$Logger.Write(("Writing to log file  :`r`n`tPath:  {0}" -f $Logger.GetLoggingFileFull()), "Force")
$Logger.Write(("Current Logging Level:  {0}" -f $Logger.GetLoggingLevel()), "Force")
########################################
    #region Get Input Files
########################################
# Check if the input file(s) were specified.
if (($null -ne $script:_scriptConfig["Inputs"]["InputFiles"]) -and ($script:_scriptConfig["Inputs"]["InputFiles"].Count -gt 1))
{
    # There are at least 2 input files specified.
    $Logger.Write(("Input files specified:  {0}" -f $script:_scriptConfig["Inputs"]["InputFiles"].Count), "Information")
}
elseif (($null -ne $script:_scriptConfig["Inputs"]["InputFiles"]) -and ($script:_scriptConfig["Inputs"]["InputFiles"].Count -eq 1))
{
    # There is only 1 possible input file.  A blank string can show up as 1.
    $_inputFileType = $script:_scriptConfig["Inputs"]["InputFiles"].GetType()
    # System.String
    # System.Object[]
    if ($_inputFileType.FullName -ieq "System.String")
    {
        # The object is a string.  Test it.
        if (($null -ne $script:_scriptConfig["Inputs"]["InputFiles"]) -and ($script:_scriptConfig["Inputs"]["InputFiles"] -ne ""))
        {
            # Convert to an array
            $script:_scriptConfig["Inputs"]["InputFiles"] = @($script:_scriptConfig["Inputs"]["InputFiles"])
        }
        else
        {
            $script:_scriptConfig["Inputs"]["InputFiles"] = Get-InputFiles -StartLocation Get-Location
        }
    }
    elseif ($_inputFileType.FullName -ieq "System.Object[]")
    {
        # The object is an array with 1 entry.  Test the first item.
        if (($null -ne $script:_scriptConfig["Inputs"]["InputFiles"][0]) -and ($script:_scriptConfig["Inputs"]["InputFiles"][0] -ne ""))
        {
            # Do Nothing
        }
        else
        {
            #
            $script:_scriptConfig["Inputs"]["InputFiles"] = Get-InputFiles -StartLocation Get-Location
        }
    }
    else
    {
        # Unknown object for the Inputs InputFiles.  Ask for file selection
        $script:_scriptConfig["Inputs"]["InputFiles"] = Get-InputFiles -StartLocation Get-Location
    }
}
else
{
    # Warning
    $Logger.Write("No input file(s) specified!", "Warning")

    # Ask the user to select the file(s).
    $script:_scriptConfig["Inputs"]["InputFiles"] = Get-InputFiles -StartLocation Get-Location
}
#endRegion Get Input Files
########################################
########################################
    #region Analyze Input Files
########################################
# Analyze the Input file(s).
$Logger.Write("Analyzing the input file(s).", "Information")

# Create a variable to hold the information.
$_allInputData = $null

# Loop over the file(s).  Combine the files into a single object.
foreach ($inputFile in $script:_scriptConfig["Inputs"]["InputFiles"])
{
    # Try to get the file details.
    $_fileDetails = Get-Item $inputFile

    # Output the details.
    $Logger.Write(("        Input File   :  {0}" -f $inputFile), "Force")
    $Logger.Write(("    File Name Only   :  {0}" -f $_fileDetails.BaseName), "Information")
    $Logger.Write(("    File Extension   :  {0}" -f $_fileDetails.Extension), "Information")
    $Logger.Write(("Fully Qualified Path :  {0}" -f $_fileDetails.FullName), "Information")
    $Logger.Write(("         File Size   :  {0:N}KB" -f $_fileDetails.Length), "Information")
    
    # Import the CSV file.
    $_thisCSV = Import-Csv -Path $_fileDetails.FullName

    # Status
    $Logger.Write(("      Rows Imported  :  {0:N0}" -f $_thisCSV.Count), "Information")

    # Add the individual CSV data to the rest.
    $_allInputData += $_thisCSV
}

# All of the data has been read.  Need to dedupe and seperate the hosts.
$Logger.Write(("Total Rows Imported  :  {0}" -f $_allInputData.Count), "Information")

# Sort and deduplicate.
$_sortedInputData = $_allInputData | Sort-Object Hostname,ServiceName -Unique

$Logger.Write(("Sorted & Unique Rows :  {0}" -f $_sortedInputData.Count), "Information")

# Build a list of server admin credentials needed.  Forcing to System.Object[] so it is always an array.
[System.Object[]]$_adminCreds = $_sortedInputData | Sort-Object AdminSafe,AdminUser,AdminAddress -Unique | Select-Object @{Name="Safename"; Expression={$($_.AdminSafe)}}, @{Name="Username"; Expression={$($_.AdminUser)}}, @{Name="Address"; Expression={$($_.AdminAddress)}}

$Logger.Write(("Admin Creds Needed   :  {0}" -f $_adminCreds.Count), "Information")

# Build a list of service credentials needed.  Forcing to System.Object[] so it is always an array.
[System.Object[]]$_serviceCreds = $_sortedInputData | Sort-Object ServiceSafe,ServiceUser,ServiceAddress -Unique | Select-Object @{Name="Safename"; Expression={$($_.ServiceSafe)}}, @{Name="Username"; Expression={$($_.ServiceUser)}}, @{Name="Address"; Expression={$($_.ServiceAddress)}}
#Select-Object ServiceSafe,ServiceUser,ServiceAddress

$Logger.Write(("Service Creds Needed :  {0}" -f $_serviceCreds.Count), "Information")
#endRegion Analyze Input Files
########################################
# Get the CyberArk Authentication Token.
$Logger.Write("Authenticating to the PVWA.", "Information")

# Get a new CyberArk / psPAS session.  Build a hash table to hold the attributes.
$newSessionAttributes = @{
    AuthMethod = $script:_scriptConfig["CyberArk_PVWA"]["User_Authentication"]
    Address = $script:_scriptConfig["CyberArk_PVWA"]["Address"]
    Scheme = $script:_scriptConfig["CyberArk_PVWA"]["HTTP_Scheme"]
    Port = $script:_scriptConfig["CyberArk_PVWA"]["Port"]
    Application  = $script:_scriptConfig["CyberArk_PVWA"]["Application"]
    IgnoreSSLErrors = $script:_scriptConfig["CyberArk_PVWA"]["IgnoreSSLErrors"]
    ThumbPrint = $script:_scriptConfig["Inputs"]["ThumbPrint"]
}
# Make the request using the previously built hash table. No data returned.
$null = New-CyberArkSession @newSessionAttributes

# Get the server admin credential(s).
$Logger.Write("Getting server admin Account(s).", "Information")
$_adminAccounts = Get-AllAccounts -Accounts $_adminCreds -Unlock $script:_scriptConfig["Inputs"]["Unlock"]

# Get the content for all server admin accounts.
$_adminCredentials = Get-AllAccountContent -Accounts $_adminAccounts -Reason $script:_scriptConfig["Inputs"]["Reason"]

# Output the status of the Admin Credentials.
$Logger.Write(("Admin Credentials Retrieved ({0})." -f $_adminCredentials.Count), "Information")

# Get the service account details.
$Logger.Write("Getting service Account(s).", "Information")
$_serviceCredentials = Get-AllAccounts -Accounts $_serviceCreds -Unlock $script:_scriptConfig["Inputs"]["Unlock"]

# Output the status of the service account Credentials.
$Logger.Write(("Service Account(s) Retrieved ({0})." -f $_serviceCredentials.Count), "Information")

# Stop the services.
$Logger.Write("Stopping services.", "Information")

$_stopSetService = @{
    AdminCreds = $_adminCredentials
    TargetServices = $_sortedInputData
    Action = "Stop"
    MaxThreads  = $script:_scriptConfig["Threads"]["Max"]
}
$stopResult = Set-ServiceProperties @_stopSetService

# Check if the Service Account password(s) should be changed automatically.
if (($null -ne $script:_scriptConfig["Inputs"]["RotateServicePassword"]) -and ($script:_scriptConfig["Inputs"]["RotateServicePassword"]))
{
    # Call Password Reset function.
    $rapResult = Reset-AccountPassword -Accounts $_serviceCredentials
    
}
else
{
    # Wait for the user to continue.
    $Logger.Write(("********** User Action Required **********"), "Warning")
    $Logger.Write(("******************************************
    `tUser must validate that the Password(s) for the Service Account(s)
    `thave been rotated and is valid before continuing."), "Warning")
    $null = Read-Host -Prompt "Press Enter/Return when ready."
}

# Get the service account credential(s).
$Logger.Write("Getting service credential(s).", "Information")

# Get the content for all service accounts in the array.
$resultServiceAccountContent = Get-AllAccountContent -Accounts $_serviceCredentials -Reason $script:_scriptConfig["Inputs"]["Reason"]

# Update the password on the services.
$Logger.Write("Updating services with new password.", "Information")

# Create a variable to hold the required properties for Set-ServiceProperties.
$_ProsSetService = @{
    AdminCreds = $_adminCredentials
    TargetServices = $_sortedInputData
    Action = "Update"
    ServiceCreds = $resultServiceAccountContent
    MaxThreads  = $script:_scriptConfig["Threads"]["Max"]
}
$setResult = Set-ServiceProperties @_ProsSetService

# Start the services.
$Logger.Write("Starting services.", "Information")

$_startSetService = @{
    AdminCreds = $_adminCredentials
    TargetServices = $_sortedInputData
    Action = "Start"
    MaxThreads  = $script:_scriptConfig["Threads"]["Max"]
}
$startResult = Set-ServiceProperties @_startSetService

# Check service status.
$Logger.Write("Getting service status.", "Information")

$_statusSetService = @{
    AdminCreds = $_adminCredentials
    TargetServices = $_sortedInputData
    Action = "Status"
    MaxThreads  = $script:_scriptConfig["Threads"]["Max"]
}
$statusResult = Set-ServiceProperties @_statusSetService

# Release the server admin credential(s).
$Logger.Write("Releasing the server administrator credential(s).", "Information")

$relResult = Submit-ReleaseAllAccounts -Accounts $_adminAccounts

# Ending message
$Logger.Write("**************************************************", "Information")
$Logger.Write("******************** Finished ********************", "Force")
$Logger.Write("**************************************************", "Information")

#endRegion Flow