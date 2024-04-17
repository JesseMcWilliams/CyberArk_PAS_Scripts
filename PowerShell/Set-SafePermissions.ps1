<#
    .SYNOPSIS
    This script will set or remove the permissions specified in the input file(s).
    
    .DESCRIPTION
    This script will process one or more CSV files and perform the requested Safe Permission actions.
    Valid Actions:  Add, Update, Remove.
    
    The input CSV file needs to have the following header.
        SafeName , UserType , Username ,Domain , Action , Role
    
        SafeName: This is the name of the safe to modify the owners list on.

        UserType: This is the type of owner to be processed.  Valid values:  User / Group

        UserName: This is the Username / SAMAccountName of the owner to be processed.

        Domain  : This can be blank for Internal CyberArk Groups or Users.
                  For domain Users or Groups use the LDAP Integration Name for domain based Users and Groups.

        Action  : Add - Add new owner to safe / Update - Modify owner permissions on safe / Remove - Remove the safe owner.

          Role  : This is the name of the Local CyberArk Group used to represent a role.
                  This group should be assigned the role's permissions on the Template Safe.
    
    A Template Safe (Z_Template_Safe_Permissions) is needed for the script to perform the requested actions.

    Local CyberArk Groups are needed for the script to perform lookups of the role on the Template Safe.
    Role Groups should start with the same prefix like "RG_".

    This script is written for PVWA version 12.2 or higher.
    This script requires PowerShell 5.1 or higher.
    
    .PARAMETER PVWAURL
    [string]: This is the base URL of the PVWA web server.  https://epv.company.com

    .PARAMETER AuthMethod
    [string]:  This can be one of the following:  CyberArk, LDAP, SAML, PKI, or PKIPN

    .PARAMETER Credential
    [pscredential]:  This is a PowerShell credential object.  Needed for CyberArk and LDAP authentication.

    .PARAMETER Thumbprint
    [string]:  This is the User's X509 Client Authentication certificates thumbprint.  Needed for PKI or PKIPN authentication.

    .PARAMETER RequestTimeout
    [int]:  This is the time in seconds that each request can take before timing out.
    
    .PARAMETER IISAppName
    [string]:  This is the name of the IIS application.  Normally PasswordVault.
    
    .PARAMETER SkipCertificateCheck
    [switch]:  This will skip the validation of the remote server's certificate.

    .PARAMETER TemplateSafe
    [string]:  The name of the safe to look up role permissions.

    .PARAMETER RoleNamePrefix
    [string]:  The prefix used to specify Local CyberArk Groups that represent a permission role.

    .PARAMETER InputFiles
    [string[]]:  An array holding one or more file names.

    .OUTPUTS
    Output can be sent to standard out or to a file.

    .NOTES
    This script leverages the work of the following people and more.
        https://github.com/allynl93
        https://github.com/infamousjoeg
        https://github.com/pspete

    .LINK
    https://github.com/allynl93/getSAMLResponse-Interactive

    .LINK
    https://github.com/allynl93/getSAMLResponse-Interactive/releases

    .EXAMPLE
    This example is the most basic.  The user needs to have updated the PVWAURL, TemplateSafe, and RoleNamePrefix in the script.

    .\Set-SafePermissions.ps1

    .EXAMPLE
    In this example the user's credential is stored in the variable $MyCred to allow repeat running of the script without having to re-enter 
    the credentials.  The user needs to have updated the PVWAURL, TemplateSafe, and RoleNamePrefix in the script.

    $MyCred = Get-Credential
    .\Set-SafePermissions.ps1 -Credential $MyCred

    .EXAMPLE
    In this example all required arguments are specified on the command line.

    .\Set-SafePermissions.ps1 -PVWAURL "https://epv.company.com" -TemplateSafe "Z_Template_Safe_Permissions" -RoleNamePrefix "RG_" -InputFiles @("Input_Safe_Permissions_1.csv","Input_Safe_Permissions_2.csv")

    .EXAMPLE
    In this example a DOS / Command Line batch script is used to call the script.  The "^" carrot at the end is needed for line wrapping.
    Create a DOC/Batch file name:  Set-SafePermissions.bat
    Contnets:
        CLS
        @Echo Off

        set PVWAURL=https://epv.company.com
        set AuthMethod=CyberArk
        set TemplateSafe=Z_Template_Safe_Permissions
        set RoleNamePrefix=RG_
        set InputFiles=!Input_SafePermissions.csv

        Echo Launching PowerShell script!
        PowerShell -NoProfile -ExecutionPolicy Bypass -File ".\Set-SafePermissions.ps1" ^
        -PVWAURL "%PVWAURL%" -AuthMethod "%AuthMethod%" -TemplateSafe "%TemplateSafe%" ^
        -RoleNamePrefix "%RoleNamePrefix%" -InputFiles %InputFiles% -SkipCertificateCheck
#>

[CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $PVWAURL = "https://192.168.184.128",

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
            [ValidateSet('CyberArk','LDAP','SAML','PKI','PKIPN')]
        [string] $AuthMethod = "CyberArk",
    
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [pscredential] $Credential = $MyCred,
        #(New-Object System.Management.Automation.PSCredential ("CA_Jesse", (ConvertTo-SecureString "Password22!" -AsPlainText -Force)))

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $ThumbPrint,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [int] $RequestTimeout = 30,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $IISAppName = "PasswordVault",

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [switch] $SkipCertificateCheck,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $TemplateSafe = "Z_Template_Safe_Permissions",

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $RoleNamePrefix = "RG_",

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string[]] $InputFiles
    )

# Enable Verbose Logging :  
#$VerbosePreference='Continue'

# Disable Verbose Logging:  
$VerbosePreference='SilentlyContinue'

$SkipCertificateCheck = $true


##########################################################
#region URL Stubs
##########################################################
# Authentication
$AUTHURLS = @{
    "CyberArk" = @{
        URL = "/API/auth/cyberark/logon"
        Method = "POST"
    }
    "LDAP" = @{
        URL = "/API/auth/ldap/logon"
        Method = "POST"
    }
    "SAML" = @{
        URL = "/API/auth/saml/logon"
        Method = "POST"
    }
    "RADIUS" = @{
        URL = "/API/auth/radius/logon"
        Method = "POST"
    }
    "PKI" = @{
        URL = "/API/auth/pki/logon"
        Method = "POST"
    }
    "PKIPN" = @{
        URL = "/API/auth/pkipn/logon"
        Method = "POST"
    }
    "LogOff" = @{
        URL = "/API/auth/logoff"
        Method = "POST"
    }
}
# Safe
$SAFEURLS = @{
    "AddSafe" = @{
        URL = "/API/Safes/"
        Method = "POST"
    }
    "UpdateSafe" = @{
        URL = "/API/Safes/{SafeUrlId}/"
        Method = "PUT"
    }
    "DeleteSafe" = @{
        URL = "/API/Safes/{SafeUrlId}/"
        Method = "DELETE"
    }
    "SearchSafe" = @{
        URL = "/WebServices/PIMServices.svc/Safes?query={Query}/"
        Method = "GET"
    }
    "GetAllSafes" = @{
        URL = "/API/Safes/"
        Method = "GET"
    }
    "GetSafeDetails" = @{
        URL = "/API/Safes/{SafeUrlId}/"
        Method = "GET"
    }
    "GetSafeByPlatform" = @{
        URL = "/API/Platforms/{PlatformID}/Safes/"
        Method = "GET"
    }
}
# Safe Members
$SAFEMEMBERSURLS = @{
    "AddSafeMember" = @{
        URL = "/API/Safes/{SafeUrlId}/Members/"
        Method = "POST"
    }
    "UpdateSafeMember" = @{
        URL = "/API/Safes/{SafeUrlId}/Members/{MemberName}/"
        Method = "PUT"
    }
    "DeleteSafeMember" = @{
        URL = "/API/Safes/{SafeUrlId}/Members/{MemberName}/"
        Method = "DELETE"
    }
    "GetSafeMember" = @{
        URL = "/API/Safes/{SafeUrlId}/Members/{MemberName}/"
        Method = "GET"
    }
    "GetAllSafeMembers" = @{
        URL = "/API/Safes/{SafeUrlId}/Members/"
        Method = "GET"
    }
}
# Accounts
$ACCOUNTSURLS = @{
    "GetAccounts" = @{
        URL = "/API/Accounts?search={search}&searchType={searchType}&sort={sort}&offset={offset}&limit={limit}&filter={filter}/"
        Method = "GET"
    }
    "GetAccountDetails" = @{
        URL = "/API/Accounts/{id}/"
        Method = "GET"
    }
    "GetAccountActivity" = @{
        URL = "/WebServices/PIMServices.svc/Accounts/{AccountID}/Activities/"
        Method = "GET"
    }
    "GetSecretVersions" = @{
        URL = "/API/Accounts/<AccountID>/Secret/Versions/"
        Method = "GET"
    }
    "AddAccount" = @{
        URL = "/api/Accounts"
        Method = "POST"
    }
    "UpdateAccount" = @{
        URL = "/API/Accounts/{AccountID}/"
        Method = "PATCH"
    }
    "DeleteAccount" = @{
        URL = "/API/Accounts/{id}/"
        Method = "DELETE"
    }
}
$ACCOUNTACTIONSURLS = @{
    "GetJustInTimeAccess" = @{
        URL = "/api/Accounts/{accountId}/grantAdministrativeAccess/"
        Method = "POST"
    }
    "RevokeJustInTimeAccess" = @{
        URL = "/api/Accounts/{accountId}/RevokeAdministrativeAccess/"
        Method = "POST"
    }
    "UnlockAccount" = @{
        URL = "/API/Accounts/<AccountID>/Unlock/"
        Method = "POST"
    }
    "ConnectUsingPSM" = @{
        URL = "/API/Accounts/{accountId}/PSMConnect/"
        Method = "POST"
    }
    "AdHocConnectUsingPSM" = @{
        URL = "/API/Accounts/AdHocConnect/"
        Method = "POST"
    }
    "GetPasswordValue" = @{
        URL = "/API/Accounts/{accountId}/Password/Retrieve/"
        Method = "POST"
    }
    "GeneratePassword" = @{
        URL = "/API/Accounts/<AccountID>/Secret/Generate/"
        Method = "POST"
    }
    "RetrievePrivateSSHKeyAccount" = @{
        URL = "/API/Accounts/{accountId}/Secret/Retrieve/"
        Method = "POST"
    }
    "CheckInExclusiveAccount" = @{
        URL = "/API/Accounts/<AccountID>/CheckIn/"
        Method = "POST"
    }
    "VerifyCredentials" = @{
        URL = "/API/Accounts/<AccountID>/Verify/"
        Method = "POST"
    }
    "ChangeCredentialsImmediately" = @{
        URL = "/API/Accounts/<AccountID>/Change/"
        Method = "POST"
    }
    "ChangeCredentialsSetNextPassword" = @{
        URL = "/API/Accounts/<AccountID>/SetNextPassword/"
        Method = "POST"
    }
    "ChangeCredentialsInTheVault" = @{
        URL = "/API/Accounts/<AccountID>/Password/Update/"
        Method = "POST"
    }
    "ReceoncileCredentials" = @{
        URL = "/API/Accounts/<AccountID>/Reconcile/"
        Method = "POST"
    }
}
$LINKEDACCOUNTSURLS = @{
    "LinkAnAccount" = @{
        URL = "/API/Accounts/{accountId}/LinkAccount/"
        Method = "POST"
    }
    "UnlinkAnAccount" = @{
        URL = "/API/Accounts/{accountId}/LinkAccount/{extraPasswordIndex}/"
        Method = "DELETE"
    }
}
$DISCOVEREDACCOUNTSURLS = @{
    "AddDiscoveredAccounts" = @{
        URL = "/API/DiscoveredAccounts/"
        Method = "POST"
    }
    "GetDiscoveredAccounts" = @{
        URL = "/API/DiscoveredAccounts/"
        Method = "GET"
    }
    "GetDiscoveredAccountDetails" = @{
        URL = "/API/DiscoveredAccounts/{id}/"
        Method = "GET"
    }
    "DeleteDiscoveredAccounts" = @{
        URL = "/API/DiscoveredAccounts/"
        Method = "DELETE"
    }
}
# Users
$USERSURLS = @{
    "GetUsers" = @{
        URL = "/API/Users/"
        Method = "POST"
    }
    "GetUserTypes" = @{
        URL = "/API/UserTypes/"
        Method = "POST"
    }
    "GetUserDetails" = @{
        URL = "/API/Users/{UserID}/"
        Method = "POST"
    }
    "GetLoggedOnUserDetails" = @{
        URL = "/WebServices/PIMServices.svc/User/"
        Method = "POST"
    }
    "AddUser" = @{
        URL = "/API/Users/"
        Method = "POST"
    }
    "UpdateUser" = @{
        URL = "/API/Users/{userID}/"
        Method = "PUT"
    }
    "DeleteUser" = @{
        URL = "/API/Users/{UserID}/"
        Method = "DELETE"
    }
    "ActivateUser" = @{
        URL = "/API/Users/{UserID}/Activate/"
        Method = "POST"
    }
    "EnableUser" = @{
        URL = "/API/Users/{UserID}/enable/"
        Method = "POST"
    }
    "DisableUser" = @{
        URL = "/API/Users/{UserID}/disable/"
        Method = "POST"
    }
    "ResetUserPassword" = @{
        URL = "/API/Users/{UserID}/ResetPassword/"
        Method = "POST"
    }
}
# Group
$GROUPSURLS = @{
    "GetGroups" = @{
        URL = "/API/UserGroups/"
        Method = "POST"
    }
    "GetGroupDetails" = @{
        URL = "/API/UserGroups/{ID}/"
        Method = "POST"
    }
    "CreateGroup" = @{
        URL = "/API/UserGroups/"
        Method = "POST"
    }
    "UpdateGroup" = @{
        URL = "/API/UserGroups/{groupId}/"
        Method = "PUT"
    }
    "DeleteGroup" = @{
        URL = "/API/UserGroups/{GroupID}/"
        Method = "DELETE"
    }
    "AddMemberToGroup" = @{
        URL = "/API/UserGroups/{id}/Members/"
        Method = "POST"
    }
    "RemoveUserFromGroup" = @{
        URL = "/API/UserGroups/{groupID}/Members/{member}/"
        Method = "DELETE"
    }
}
# SSH Keys
$PUBLICSSHURLS = @{
    "GetPublicSSHKeys" = @{
        URL = "/WebServices/PIMServices.svc/Users/{UserName}/AuthenticationMethods/SSHKeyAuthentication/AuthorizedKeys/"
        Method = "GET"
    }
    "AddPublicSSHKey" = @{
        URL = "/WebServices/PIMServices.svc/Users/{UserName}/AuthenticationMethods/SSHKeyAuthentication/AuthorizedKeys/"
        Method = "POST"
    }
    "DeletePublicSSHKey" = @{
        URL = "/WebServices/PIMServices.svc/Users/{UserName}/AuthenticationMethods/SSHKeyAuthentication/AuthorizedKeys/{KeyID}/"
        Method = "DELETE"
    }
}

$PRIVATESSHURLS = @{
    "GenerateMFACaching" = @{
        URL = "/API/Users/Secret/SSHKeys/Cache/"
        Method = "POST"
    }
    "GenerateMFACachingAnotherUser" = @{
        URL = "/API/Users/{userID}/Secret/SSHKeys/Cache/"
        Method = "POST"
    }
    "DeleteMFACaching" = @{
        URL = "/API/Users/Secret/SSHKeys/Cache/"
        Method = "DELETE"
    }
    "DeleteMFACachingAnotherUser" = @{
        URL = "/API/Users/{userID}/Secret/SSHKeys/Cache/"
        Method = "DELETE"
    }
    "DeleteAllMFACaching" = @{
        URL = "/API/Users/Secret/SSHKeys/ClearCache/"
        Method = "DELETE"
    }
}

#endRegion URLs

##########################################################
#region Error Codes & Messages
##########################################################
$ERRORMESSAGES = @{
    20 = "No Credential Provided!"
    21 = "Failed to get CyberArk Authentication Token!"
    22 = "No Credential Provided or Password too short!"
    30 = "No File(s) Provided!"
    100 = "Invalid URL!"
}
#endRegion Error Codes & Messages

##########################################################
#region HTTP Return Codes
##########################################################
$RETURNCODES = @{
    200 = @{
        Code = "Success"
        Description = "The request succeeded. The actual response will depend on the request method used."
        Retry = $false
    }

    201 = @{
        Code = "Created"
        Description = "The request was fulfilled and resulted in a new resource being created."
        Retry = $false
    }

    204 = @{
        Code = "No Content"
        Description = "The server successfully processed the request and is not returning any content (no response body). This code is typically returned by DELETE requests."
        Retry = $false
    }

    400 = @{
        Code = "Bad Request"
        Description = "The request could not be understood by the server due to incorrect syntax."
        Retry = $false
    }

    401 = @{
        Code = "Unauthorized"
        Description = "The request requires user authentication."
        Retry = $false
    }

    403 = @{
        Code = "Forbidden"
        Description = "The server received and understood the request, but will not fulfill it. Authorization will not help and the request MUST NOT be repeated."
        Retry = $false
    }

    404 = @{
        Code = "Not Found"
        Description = "The server did not find anything that matches the Request-URI. No indication is given of whether the condition is temporary or permanent."
        Retry = $false
    }

    409 = @{
        Code = "Conflict"
        Description = "The request could not be completed due to a conflict with the current state of the resource."
        Retry = $false
    }

    429 = @{
        Code = "Too Many Requests"
        Description = 'The user has sent too many requests in a given amount of time ("rate limiting").'
        Retry = $false
    }

    500 = @{
        Code = "Internal Server Error"
        Description = "The server encountered an unexpected condition which prevented it from fulfilling the request."
        Retry = $false
    }

    501 = @{
        Code = "Not Implemented"
        Description = "The server does not support this operation due to version incompatibility."
        Retry = $false
    }

}
#endRegion HTTP Return Codes

##########################################################
#region Global Variables
##########################################################
# The Web Session variable is needed for load balancers.
#$WEBSESSION = [Microsoft.PowerShell.Commands.WebRequestSession]::New()

# UNIX epoch time origin
$UNIXORIGIN = [System.DateTime]::New(1970,01,01,00,00,00)

# Map Authentication Methods to the required credential type.
$AUTHTYPEREQ = @{
    "CyberArk" = "Credential"
    "LDAP" = "Credential"
    "SAML" = "None"
    "RADIUS" = "None"
    "PKI" = "ThumbPrint"
    "PKIPN" = "ThumbPrint"
}
#endRegion Global Variables

##########################################################
#region Helper Functions
##########################################################
function Stop-Exit
{
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [int] $Code,
        
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $Message
    )
    # This will end script execution and exit.
    # Check if an alternate message was provided.
    if (($null -eq $Message) -or ($Message -eq ""))
    {
        # Use alternate message.
        $Message = $ERRORMESSAGES[$Code]
    }
    
    Write-Warning ("{0} : Exit Requested : Code ({1:d4}) : {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Code, $Message)

    Write-Error ("{0} : Exit Requested : Code ({1:d4}) : {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Code, $Message)
    
    # Exit the script
    Exit $Code
}

function Get-InputFiles
{
	[cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $false
        )]
        [string]$StartLocation,

		[parameter(
            Mandatory = $false,
            ValueFromPipeline = $false
        )]
        [string]$FileFilter = "CSV files (*.csv)|*.csv|TXT files (*.txt)|*.txt|All files (*.*)|*.*"
    )

    Begin{
        # Add the windows form to this script
        Add-Type -AssemblyName System.Windows.Forms

        # Create the file browser object
        $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog
        $FileBrowser.Filter = $FileFilter
        $FileBrowser.FilterIndex = 0
        $FileBrowser.Multiselect = $true

        # Check if a start location has been specified
        if ($StartLocation)
        {
            # Set the starting location to the requested location
            $FileBrowser.InitialDirectory = $StartLocation
        }
        else
        {
            $FileBrowser.InitialDirectory = [Environment]::GetFolderPath('Desktop')
        }
    }

    Process{
        # Open the file browser.  The data returned by the object is not needed.
        #  The selected files are a property of the object
        $null = $FileBrowser.ShowDialog()
        return $FileBrowser.FileNames
    }

	<#
    .SYNOPSIS
    This function will open the file dialog box and allow you to choose 1 or more files.

    .PARAMETER StartLocation
    You can specify the folder to start in.

    .OUTPUTS
    Returns an Array of strings
    The strings are the full path to the selected file(s)
    #>
}

function Get-Folder
{
	[cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $false
        )]
        [string]$StartLocation
    )

    Begin{
		# Add the windows form to this script
		Add-Type -AssemblyName System.Windows.Forms

		# Create the file browser object
		$FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog

		# Check if a start location has been specified
		if ($StartLocation)
		{
			# Set the starting location to the requested location
			$FolderBrowser.InitialDirectory = $StartLocation
		}
		else
		{
			$FolderBrowser.InitialDirectory = [Environment]::GetFolderPath('Desktop')
		}
	}

	Process{
		# Open the file browser.  The data returned by the object is not needed.
        #  The selected files are a property of the object
        $null = $FolderBrowser.ShowDialog()
        return $FolderBrowser.SelectedPath
	}
}

function Get-OutputFile
{
	[cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $false
        )]
        [string]$StartLocation,

		[parameter(
            Mandatory = $false,
            ValueFromPipeline = $false
        )]
        [string]$DefaultExtension = ".CSV",

		[parameter(
            Mandatory = $false,
            ValueFromPipeline = $false
        )]
        [string]$FileFilter = "CSV files (*.csv)|*.csv|TXT files (*.txt)|*.txt|All files (*.*)|*.*"
    )

    Begin{
        # Add the windows form to this script
        Add-Type -AssemblyName System.Windows.Forms

        # Create the file browser object
        $FileBrowser = New-Object System.Windows.Forms.SaveFileDialog
		$FileBrowser.Filter = $FileFilter
        $FileBrowser.FilterIndex = 0
        $FileBrowser.DefaultExt = $DefaultExtension

        # Check if a start location has been specified
        if ($StartLocation)
        {
            # Set the starting location to the requested location
            $FileBrowser.InitialDirectory = $StartLocation
        }
        else
        {
            $FileBrowser.InitialDirectory = [Environment]::GetFolderPath('Desktop')
        }
    }

    Process{
        # Open the file browser.  The data returned by the object is not needed.
        #  The selected files are a property of the object
        $null = $FileBrowser.ShowDialog()
        return $FileBrowser.FileNames
    }

	<#
    .SYNOPSIS
    This function will open the file save dialog box and allow you to choose or set the output file.

    .PARAMETER StartLocation
    You can specify the folder to start in.

    .OUTPUTS
    Returns an Array of strings
    The strings are the full path to the selected file(s)
    #>

}

function Get-UserCertificate
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $false
        )]
        [string]$Message,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $false
        )]
        [string]$Thumbprint
    )

    Begin{
        if (!$Thumbprint)
        {
            # Add the windows form to this script
            Add-Type -AssemblyName System.Security

            # Get all certificates from the user's certificate store.
            $_userCertificates = Get-ChildItem -Path "Cert:\CurrentUser\My\" -Eku "*Client Authentication*"

            # Filter the client authentication certificates that have a private key.
            $_hasPrivateKeyCerts = $_userCertificates | Where-Object HasPrivateKey -EQ $true

            # Filter the client authentication certificates that are within the date range.
            $_notExpiredCerts = $_hasPrivateKeyCerts | Where-Object NotAfter -GT $(Get-Date)

            # Filter the client authentication certificates that are within the date range.
            $_isValidCerts = $_notExpiredCerts | Where-Object NotBefore -LT $(Get-Date)

            # Filter the client authentication certificates that are within the date range.
            $_isHardwareCerts = $_isValidCerts | Where-Object {$_.PrivateKey.CspKeyContainerInfo.HardwareDevice -EQ $true}

            # Create the X509 Certificate Collection
            $CertCollection = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::New($_isHardwareCerts)
        }
    }

    Process{
        # The selected certificate is returned.
        if ($Thumbprint)
        {
            # Get the certificate that matches the thumbprint
            [System.Security.Cryptography.X509Certificates.X509Certificate2]$userCertificate = Get-ChildItem -Path ("Cert:\CurrentUser\*{0}" -f $ThumbPrint) -Recurse
            return $userCertificate
        }
        else
        {
            $_userCert = [System.Security.Cryptography.X509Certificates.X509Certificate2UI]::SelectFromCollection(
                    $CertCollection, 
                    "User's Client Authentication Certificates", 
                    $Message, 
                    0
                )
                return $_userCert[0]
        }
    }

	<#
    .SYNOPSIS
    This function will open the certificate selection window to choose one..

    .PARAMETER Message
    You can specify a custom message to be displayed.

    .OUTPUTS
    Returns the thumbprint of the selected certificate.
    #>
}
#endRegion Helper Functions

##########################################################
#region Rest API Helper Functions
##########################################################
function Join-Url 
{
    <#
    .DESCRIPTION
    Join-Path but for URL strings instead
    https://www.powershellgallery.com/packages/Scrubber/0.1.0/Content/Private%5CJoin-Url.ps1
     
    .PARAMETER Path
    Base path string
     
    .PARAMETER ChildPath
    Child path or item name
     
    .EXAMPLE
    Join-Url -Path "https://www.contoso.local" -ChildPath "foo.htm"
    returns "https://www.contoso.local/foo.htm"
 
    #>
    param (
        [parameter(Mandatory=$True, HelpMessage="Base Path")]
        [ValidateNotNullOrEmpty()]
        [string] $Path,

        [parameter(Mandatory=$True, HelpMessage="Child Path or Item Name")]
        [ValidateNotNullOrEmpty()]
        [string] $ChildPath
    )
	# Setup function variables.
	$_lastCharPath = $Path.Substring(($Path.Length - 1), 1)
	$_firstCharChild = $ChildPath.Substring(0, 1)
	$_returnURL = ""

	# Choose the combination method.
    if (($_lastCharPath.Equals('/') -and ($_firstCharChild.Equals('/'))))
	{
        $_returnURL = ("{0}{1}" -f $Path, $ChildPath.Substring(1))
    }
    elseif (($_lastCharPath.Equals('/') -and ($_firstCharChild.Equals('?'))))
	{
		$_returnURL = ("{0}{1}" -f $Path.Substring(0, ($Path.Length -1)), $ChildPath)
	}
	elseif ((-not $_lastCharPath.Equals('/') -and ($_firstCharChild.Equals('/'))))
	{
		$_returnURL = ("{0}{1}" -f $Path, $ChildPath)
	}
	elseif (($_lastCharPath.Equals('/') -and (-not $_firstCharChild.Equals('/'))))
	{
		$_returnURL = ("{0}{1}" -f $Path, $ChildPath)
	}
    else 
	{
        $_returnURL = ("{0}/{1}" -f $Path, $ChildPath)
    }

	# return URL
	Write-Verbose ("{0} : Join-URL : Base ({1}) : Child ({2}) : `r`n`tJoined ({3})" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Path, $ChildPath, $_returnURL)
	return $_returnURL
}

function Get-QueryParameterString
{
    <#
	.SYNOPSIS
	Converts a Dictionary / Hash Table to a query string

	.DESCRIPTION
	Pass in a Dictionary / Hash Table and a full URI will be returned.

	.PARAMETER BaseURL
	The base URL to be appended to.

    .PARAMETER QueryParameters
    The Dictionary/Hashtable of the query parameters

    .OUTPUT
    A full URL/URI with query parameter appended.

	.EXAMPLE
	$WebResponseObject | Get-PASResponse

	Parses, if required, and returns, the required properties of $WebResponseObject

	#>
	[CmdletBinding()]
	[OutputType('System.String')]
	param(
		[parameter(
			Position = 0,
			Mandatory = $true,
			ValueFromPipeline = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$BaseURI,

        [parameter(
			Position = 1,
			Mandatory = $true,
			ValueFromPipeline = $true)]
		[ValidateNotNullOrEmpty()]
		[hashtable]$QueryParameters

	)

    # Check for trailing slash on BaseURI.
    if ($BaseURI.Substring(($BaseURI.Length -1), 1) -eq "/")
    {
        $BaseURI = $BaseURI.Substring(0, ($BaseURI.Length -1))
    }

    # String to hold the value to be returned.
    $ReturnString = ""

    # Build the Query string
    $_QPString = ""
    foreach ($qpEnt in $QueryParameters.Keys)
    {
        if ($_QPString -eq "")
        {
            $_QPString = ("?{0}={1}" -f $qpEnt, $QueryParameters[$qpEnt])
        }
        else
        {
            $_QPString += ("&{0}={1}" -f $qpEnt, $QueryParameters[$qpEnt])
        }
    }
    $ReturnString = Join-Url -Path $BaseURI -ChildPath $_QPString

    return $ReturnString
}

function Get-QueryFilterString 
{
    [CmdletBinding()]
	[OutputType('System.String')]
	param(
		[parameter(
			Position = 0,
			Mandatory = $true,
			ValueFromPipeline = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$BaseURI,

        [parameter(
			Position = 1,
			Mandatory = $true,
			ValueFromPipeline = $true)]
		[ValidateNotNullOrEmpty()]
		[string[]]$QueryFilters

	)
    # Build the initial return URL.
    $_returnURL = $BaseURI

    # Check the last character of the url.
    $_lastChar = $_returnURL.Substring(($_returnURL.Length -1), 1)

    if ($_lastChar -eq "/")
    {
        $_returnURL = $_returnURL.Substring(0, ($_returnURL.Length -1))
        $_returnURL += "?"
    }
    elseif (($_lastChar -eq "&") -and (!$_returnURL.Contains("?")))
    {
        # Does end with & but does NOT contain ?.
        # Count the &.
        $_count = ($_returnURL.Length) - ($_returnURL.Remove("&").Length)

        # The count should be 1.  If higher then there is an issue.
        if ($_count -eq 1)
        {
            # Add a trailing ?.
            $_returnURL = $_returnURL.Replace("&", "?")
        }
        else
        {
            # Error
            $_errorCode = 100

            Write-Error ("{0} : {1}" -f $ERRORMESSAGES[$_errorCode], $BaseURI)

            throw $_errorCode
        }

    }
    elseif (($_lastChar -ne "&") -and (!$_returnURL.Contains("?")))
    {
        # Does not end with & and does not contain ?.
        # Last char needs to be ?.
        $_returnURL += "?"
    }

    # Build the filter(s)
    if (($null -ne $QueryFilters) -and ($QueryFilters[0] -ne ""))
    {
        # Loop over the filters.
        foreach ($_filter in $QueryFilters)
        {
            $_returnURL += ("filter={0}&" -f $_filter)
        }

        # Strip the last char "&"
        $_returnURL = $_returnURL.Substring(0, ($_returnURL.Length -1))
    }

    # Return the URI
    return $_returnURL
}
#endRegion Rest API Helper Functions

##########################################################
#region Rest API Support Functions
##########################################################
function Invoke-PASRestMethod 
{
	<#
	.SYNOPSIS
	Wrapper for Invoke-WebRequest to call REST method via API

	.DESCRIPTION
	Sends requests to web services. Catches Exceptions. Outputs Success.
	Acts as wrapper for the Invoke-WebRequest CmdLet so that status codes can be
	queried and acted on.
	All requests are sent with ContentType=application/json.
	If the sessionVariable parameter is passed, the function will return the WebSession
	object to the $Script:WebSession variable.
    Taken from:
    https://github.com/pspete/psPAS/blob/master/psPAS/Private/Invoke-PASRestMethod.ps1

	.PARAMETER Method
	The method for the REST Method.
	Only accepts GET, POST, PUT, PATCH or DELETE

	.PARAMETER URI
	The address of the API or service to send the request to.

	.PARAMETER Body
	The body of the request to send to the API

	.PARAMETER Headers
	The header of the request to send to the API.

	.PARAMETER SessionVariable
	If passed, will be sent to invoke-webrequest which in turn will create a websession
	variable using the string value as the name. This variable will only exist in the current scope
	so will be set as the value of $Script:WebSession to be available in a modules scope.
	Cannot be specified with WebSession

	.PARAMETER WebSession
	Accepts a WebRequestSession object containing session details
	Cannot be specified with SessionVariable

	.PARAMETER UseDefaultCredentials
	See Invoke-WebRequest
	Used for Integrated Auth

	.PARAMETER Credential
	See Invoke-WebRequest
	Used for Integrated Auth

	.PARAMETER TimeoutSec
	See Invoke-WebRequest
	Specify a timeout value in seconds

	.PARAMETER Certificate
	See Invoke-WebRequest
	The client certificate used for a secure web request.

	.PARAMETER CertificateThumbprint
	See Invoke-WebRequest
	The thumbprint of the certificate to use for client certificate authentication.

	.PARAMETER SkipCertificateCheck
	Skips certificate validation checks.

	.PARAMETER ReturnRawResponse
	Returns the raw web response.

	.EXAMPLE
	Invoke-PASRestMethod -Uri $URI -Method DELETE -WebSession $Script:WebSession

	Send request to web service
	#>
	[CmdletBinding(DefaultParameterSetName = 'WebSession')]
	param
	(
		[Parameter(Mandatory = $true)]
		[ValidateSet('GET', 'POST', 'PUT', 'DELETE', 'PATCH')]
		[String]$Method,

		[Parameter(Mandatory = $true)]
		[String]$URI,

		[Parameter(Mandatory = $false)]
		[Object]$Body,

		[Parameter(Mandatory = $false)]
		[hashtable]$Headers,

		[Parameter(
			Mandatory = $false,
			ParameterSetName = 'SessionVariable'
		)]
		[String]$SessionVariable,

		[Parameter(
			Mandatory = $false,
			ParameterSetName = 'WebSession'
		)]
		[Microsoft.PowerShell.Commands.WebRequestSession]$WebSession,

		[Parameter(Mandatory = $false)]
		[switch]$UseDefaultCredentials,

		[Parameter(Mandatory = $false)]
		[PSCredential]$Credential,

		[Parameter(Mandatory = $false)]
		[int]$TimeoutSec,

		[Parameter(Mandatory = $false)]
		[X509Certificate]$Certificate,

		[Parameter(Mandatory = $false)]
		[string]$CertificateThumbprint,

		[Parameter(Mandatory = $false)]
		[switch]$SkipCertificateCheck,

		[Parameter(Mandatory = $false)]
		[switch]$ReturnRawResponse,

		[Parameter(Mandatory = $false)]
		[string]$ContentType

	)

	Begin {

		Write-Verbose ("Invoke-PASRestMethod")
		#Set defaults for all function calls
		$ProgressPreference = 'SilentlyContinue'
		$PSBoundParameters.Add('UseBasicParsing', $true)

		if ( -not ($PSBoundParameters.ContainsKey('ContentType'))) {

			$PSBoundParameters.Add('ContentType', 'application/json')

		}

		#Bypass strict RFC header parsing in PS Core
		#Use TLS 1.2
		if (Test-IsCoreCLR) {

			$PSBoundParameters.Add('SkipHeaderValidation', $true)
			$PSBoundParameters.Add('SslProtocol', 'TLS12')

		}

		Switch ($PSBoundParameters.ContainsKey('SkipCertificateCheck')) {

			$true {

                #SkipCertificateCheck Declared
				if ( -not (Test-IsCoreCLR)) {

					#Remove parameter, incompatible with PowerShell
					$PSBoundParameters.Remove('SkipCertificateCheck') | Out-Null

					if ($SkipCertificateCheck) {

						Write-Warning ("{0} : Skipping Certificate Checks for Remote Host! {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $SkipCertificateCheck)
                        #Skip SSL Validation
						Skip-CertificateCheck
					}

				} else {

					#PWSH
					if ($SkipCertificateCheck) {

                        Write-Warning ("{0} : Skipping Certificate Checks for Remote Host! {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $SkipCertificateCheck)
						#Ongoing SSL Validation Bypass Required
						$Script:SkipCertificateCheck = $true
					}

				}

			}

			$false {

				#SkipCertificateCheck Not Declared
				#SSL Validation Bypass Previously Requested
				If ($Script:SkipCertificateCheck) {

					#PWSH Zone
					if (Test-IsCoreCLR) {

						#Add SkipCertificateCheck to PS Core command
						#Parameter must be included for all pwsh invocations of Invoke-WebRequest
						$PSBoundParameters.Add('SkipCertificateCheck', $true)

					}

				}

			}

		}

		#If Tls12 Security Protocol is available
		if (([Net.SecurityProtocolType].GetEnumNames() -contains 'Tls12') -and

			#And Tls12 is not already in use
			(-not ([System.Net.ServicePointManager]::SecurityProtocol -match 'Tls12'))) {

			[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

		}

	}

	Process {

		#Show sanitised request body if in debug mode
		If ([System.Management.Automation.ActionPreference]::SilentlyContinue -ne $DebugPreference) {

			If (($PSBoundParameters.ContainsKey('Body')) -and (($PSBoundParameters['Body']).GetType().Name -eq 'String')) {

				Write-Debug "[Body] $(Hide-SecretValue -InputValue $Body)"

			}

		}

		try {
            Write-Verbose ("{0} :          Target URI  :  `r`n`t{1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $PSBoundParameters.URI)
            Write-Verbose ("{0} : HTTP Request Method  :  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $PSBoundParameters.Method)
            Write-Verbose ("{0} :     Request Headers  :  `r`n{1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), ($PSBoundParameters.Headers | ConvertTo-Json))
            Write-Verbose ("{0} :        Content Type  :  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $PSBoundParameters.ContentType)
            Write-Verbose ("{0} :     Request Timeout  :  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $PSBoundParameters.TimeoutSec)
            Write-Verbose ("{0} : New Session Variable :  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $PSBoundParameters.SessionVariable)

            if ($PSBoundParameters.WebSession)
            {
                # An existing web session was passed.
                Write-Verbose ("{0} :  Web Session Headers :  `r`n{1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), ($PSBoundParameters.WebSession.Headers | ConvertTo-Json))
                # Assign the cookie container to a variable.
                [System.Net.CookieContainer]$_wrsCookies = $PSBoundParameters.WebSession.Cookies

                # Get the cookies from the container.
                $_selectedCookies = $_wrsCookies.GetCookies($PSBoundParameters.URI)

                # Output the cookies.
                Write-Verbose ("{0} :  Web Session Cookies :  `r`n`t{1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), ($_selectedCookies -join "`r`n`t"))
            }
            
            Write-Verbose ("{0} :   HTTP Request Body  :  `r`n{1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $PSBoundParameters.Body)
			
            #make web request, splat PSBoundParameters
			$APIResponse = Invoke-WebRequest @PSBoundParameters -ErrorAction Stop

		} catch [System.UriFormatException] {

			#Catch URI Format errors. Likely $Script:BaseURI is not set; New-PASSession should be run.
			$PSCmdlet.ThrowTerminatingError(

				[System.Management.Automation.ErrorRecord]::new(

					"$PSItem Run New-PASSession",
					$null,
					[System.Management.Automation.ErrorCategory]::NotSpecified,
					$PSItem

				)

			)

		} catch {

            $ErrorID = $null
			$StatusCode = $($PSItem.Exception.Response).StatusCode.value__
			$ErrorMessage = $($PSItem.Exception.Message)

			$Response = $PSItem.Exception | Select-Object -ExpandProperty 'Response' -ErrorAction Ignore
			if ( $Response ) {

				$ErrorDetails = $($PSItem.ErrorDetails)
			}

			# Not an exception making the request or the failed request didn't have a response body.
			if ( $null -eq $ErrorDetails ) {

				throw $PSItem

			} Else {

				If (-not($StatusCode)) {

					#Generic failure message if no status code/response
					$ErrorMessage = "Error contacting $($PSItem.TargetObject.RequestUri.AbsoluteUri)"

				} ElseIf ($ErrorDetails) {

					try {

						#Convert ErrorDetails JSON to Object
						$Response = $ErrorDetails | ConvertFrom-Json

						#API Error Message
						$ErrorMessage = "[$StatusCode] $($Response.ErrorMessage)"

						#API Error Code
						$ErrorID = $Response.ErrorCode

						#Inner error details are present
						if ($Response.Details) {

							#Join Inner Error Text to Error Message
							$ErrorMessage = $ErrorMessage, $(($Response.Details | Select-Object -ExpandProperty ErrorMessage) -join ', ') -join ': '

							#Join Inner Error Codes to ErrorID
							$ErrorID = $ErrorID, $(($Response.Details | Select-Object -ExpandProperty ErrorCode) -join ',') -join ','

						}

					} catch {

						#If error converting JSON, return $ErrorDetails
						#replace any new lines or whitespace with single spaces
						$ErrorMessage = $ErrorDetails -replace "(`n|\W+)", ' '
						#Use $StatusCode as ErrorID
						$ErrorID = $StatusCode

                    }
				}

			}

			#throw the error
			$PSCmdlet.ThrowTerminatingError(

				[System.Management.Automation.ErrorRecord]::new(

					$ErrorMessage,
					$ErrorID,
					[System.Management.Automation.ErrorCategory]::NotSpecified,
					$PSItem

				)

			)

		} finally {

			#If Session Variable passed as argument
			If ($PSCmdlet.ParameterSetName -eq 'SessionVariable') {

				#Make the WebSession available in the module scope
				Set-Variable -Name WebSession -Value $(Get-Variable $(Get-Variable sessionVariable).Value).Value -Scope Script

			}

			#If Command Succeeded
			if ($?) {

				#Status code indicates success
				If ($APIResponse.StatusCode -match '^20\d$') {

					Write-Verbose ("{0} : Request Success!  `r`n{1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $APIResponse)
                    if ($ReturnRawResponse)
					{
						$APIResponse
					}
					else
					{
						#Pass APIResponse to Get-PASResponse
						$APIResponse | Get-PASResponse
					}
					

				}

			}
            else
            {
                # Request failed.
                Write-Warning ("{0} : Request Failed!  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $ErrorMessage)
            }

		}

	}

	End { }

}

Function Test-IsCoreCLR 
{
    <#
    .SYNOPSIS
    Tests for PWSH

    .DESCRIPTION
    Returns "$true" if run from PWSH
    Returns "$false" if run from PowerShell

    .EXAMPLE
    Test-IsCoreCLR

    Returns "$true" if run from PWSH
    Returns "$false" if run from PowerShell

    #>

	if ($IsCoreCLR -or $PSEdition -eq 'Core') {

		$true

	} else {

		$false

	}

}

Function Skip-CertificateCheck 
{
	<#
	.SYNOPSIS
	Bypass SSL Validation

	.DESCRIPTION
	Enables skipping of ssl certificate validation for current PowerShell session.

	.EXAMPLE
	Skip-CertificateCheck

	#>

	$CompilerParameters = New-Object System.CodeDom.Compiler.CompilerParameters
	$CompilerParameters.GenerateExecutable = $false
	$CompilerParameters.GenerateInMemory = $true
	$CompilerParameters.IncludeDebugInformation = $false
	$CompilerParameters.ReferencedAssemblies.Add("System.DLL") | Out-Null
	$CertificatePolicy = @'
        namespace Local.ToolkitExtensions.Net.CertificatePolicy
        {
            public class TrustAll : System.Net.ICertificatePolicy
            {
                public bool CheckValidationResult(System.Net.ServicePoint sp,System.Security.Cryptography.X509Certificates.X509Certificate cert, System.Net.WebRequest req, int problem)
                {
                    return true;
                }
            }
        }
'@

	if ( -not (Test-IsCoreCLR)) {

		$CSharpCodeProvider = New-Object Microsoft.CSharp.CSharpCodeProvider
		$PolicyResult = $CSharpCodeProvider.CompileAssemblyFromSource($CompilerParameters, $CertificatePolicy)
		$CompiledAssembly = $PolicyResult.CompiledAssembly
		## Create an instance of TrustAll and attach it to the ServicePointManager
		$TrustAll = $CompiledAssembly.CreateInstance("Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll")
		[System.Net.ServicePointManager]::CertificatePolicy = $TrustAll

	}

}

function Get-PASResponse 
{
	<#
	.SYNOPSIS
	Receives and returns the content of the web response from the CyberArk API

	.DESCRIPTION
	Accepts a WebResponseObject.
	By default returns the Content property passed in the output of Invoke-PASRestMethod.
	Processes the API response as required depending on the format of the response, and
	the format required by the functions which initiated the request.

	.PARAMETER APIResponse
	A WebResponseObject, as returned from the PAS API using Invoke-WebRequest

	.EXAMPLE
	$WebResponseObject | Get-PASResponse

	Parses, if required, and returns, the required properties of $WebResponseObject

	#>
	[CmdletBinding()]
	[OutputType('System.Object')]
	param(
		[parameter(
			Position = 0,
			Mandatory = $true,
			ValueFromPipeline = $true)]
		[ValidateNotNullOrEmpty()]
		[Microsoft.PowerShell.Commands.WebResponseObject]$APIResponse

	)

	BEGIN {	}#begin

	PROCESS {

		if ($APIResponse.Content) {

			#Default Response - Return Content
			$PASResponse = $APIResponse.Content

			#get response content type
			$ContentType = $APIResponse.Headers["Content-Type"]

			#handle content type
			switch ($ContentType) {

				'text/html; charset=utf-8' {

					If ($PASResponse -match '<HTML>') {

						#Fail if HTML received from API

						$PSCmdlet.ThrowTerminatingError(

							[System.Management.Automation.ErrorRecord]::new(

								"Guru Meditation - HTML Response Received",
								$StatusCode,
								[System.Management.Automation.ErrorCategory]::NotSpecified,
								$APIResponse

							)

						)

					}

				}

				'application/json; charset=utf-8' {

					#application/json content expected for most responses.

					#Create Return Object from Returned JSON
					$PASResponse = ConvertFrom-Json -InputObject $APIResponse.Content

				}

				default {

					# Byte Array expected for files to be saved
					if ($($PASResponse | Get-Member | Select-Object -ExpandProperty typename) -eq "System.Byte" ) {

						#return content and headers
						$PASResponse = $APIResponse | Select-Object Content, Headers

						#! to be passed to `Out-PASFile`

					}

				}

			}

			#Return PASResponse
			$PASResponse

		}

	}#process

	END {	}#end

}

function Get-IdpURL
{
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $TargetURL,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [switch] $SkipCertificateCheck,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [int] $RequestTimeout = 30
    )
    Write-Verbose ("{0} : Getting IDP URL from:  `r`n`t`t{1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $TargetURL)

    # Build the headers.
    $_requestHeaders = @{
        'Accept' = 'application/json'
    }
    
    # Build the body.
    $_requestBody = @{
        'SAMLResponse' = '';
        'apiUse' = $true;
        'concurrentSession' = $false
    }
    
    # Build the hash table to hold the web request properties.
    $_requestAttributes = @{
        URI = $TargetURL
        Method = "Post"
        SessionVariable = "idpSession"
        Headers = $_requestHeaders
		Body 	= ($_requestBody | ConvertTo-Json)
        SkipCertificateCheck = $SkipCertificateCheck.IsPresent
        ContentType = "application/x-www-form-urlencoded"
    }
    
    $_result = Invoke-PASRestMethod @_requestAttributes

    Write-Verbose ("{0} : IDP URL:  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_result)

    # Return the result and the associated web session.  Even though we pass in idpSession it always sets
    #  it to WebSession with a scope of script.
    return @($_result, $WebSession)

}

function Get-SamlResponseEXE
{
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $TargetURL
    )
    Write-Verbose ("{0} : Getting SAML Response from:  `r`n`t`t{1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $TargetURL)
    #
    try
    {
        # Using the pre-compiled code written by allynl93.  https://github.com/allynl93
        $_samlResponse = .\getSAMLResponse\getSAMLResponse.exe $TargetURL
        Write-Verbose ("SAML Response:  `r`n`t**********************************`r`n{0}" -f $_samlResponse)
        Write-Verbose ("`t**********************************")
        return $_samlResponse
    }
    catch
    {
        Write-Warning "Failed to get SAML response."
        Write-Warning $_
    }
}
#endregion Rest API Support Functions

##########################################################
#region Get Authentication Token
##########################################################
function Test-AuthMethodReq
{
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $AuthMethod,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [pscredential] $Credential,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $ThumbPrint
    )
    

    # Create the return object.
    $_returnResult = @{
        "Valid" = $false
        "Type" = "None"
        "Value" = $null
    }

    # Test for the required credentials based on the authentication method.
    if ($AUTHTYPEREQ[$AuthMethod] -ieq "Credential")
    {
        # Set the credential type.
        $_returnResult.Type = $AUTHTYPEREQ[$AuthMethod]

        # The requested authentication method requires a credential to be specified.
        if ($Credential)
        {
            # Not Null.  Assume it is valid.
            $_returnResult.Valid = $true
            $_returnResult.Value = $Credential
        }
        else
        {
            # Ask the user for the credential.
            $_returnResult.Value = Get-Credential -Message ("Logon for {0}" -f $AuthMethod)

            # Verify that the credential is not null or empty.
            if (($_returnResult.Value) -and ($_returnResult.Value.Username -ne ""))
            {
                $_returnResult.Valid = $true
                $_returnResult.Value = Get-Credential
            }
        }
    }
    elseif ($AUTHTYPEREQ[$AuthMethod] -ieq "ThumbPrint")
    {
        # Set the credential type.
        $_returnResult.Type = $AUTHTYPEREQ[$AuthMethod]
        
        # The requested authentication method requires a certificate thumbprint to be specified.
        if ($ThumbPrint)
        {
            # Get the certificate with the given thumbprint.
            $_returnResult.Value = Get-UserCertificate -ThumbPrint $ThumbPrint
            
            # Verify that something was returned.
            if ($_returnResult.Value)
            {
                $_returnResult.Valid = $true
            }
        }
        else
        {
            # Ask the user to select the certificate.
            $_returnResult.Value = Get-UserCertificate -Message ("Choose a User Certificate for {0}" -f $AuthMethod)
            
            # Verify that something was returned.
            if ($_returnResult.Value)
            {
                $_returnResult.Valid = $true
            }
        }
    }
    elseif ($AUTHTYPEREQ[$AuthMethod] -ieq "None")
    {
        # Set the credential type.
        $_returnResult.Type = $AUTHTYPEREQ[$AuthMethod]
        
        # The requested authentication method does not require a credential or thumbprint to be specified.
        $_returnResult.Value = $null
        $_returnResult.Valid = $true
    }

    Write-Verbose ("{0} : Authentication Method :  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $AuthMethod)
    Write-Verbose ("{0} :   Required Attribute  :  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $AUTHTYPEREQ[$AuthMethod])
    Write-Verbose ("{0} :  Credential Username  :  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_returnResult.Value.UserName)
    Write-Verbose ("{0} : Certificate Thumbprint:  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_returnResult.Value.ThumbPrint)

    return $_returnResult
}
function Get-AuthToken
{
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $BaseURL,

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $AuthMethod,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [pscredential] $Credential,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $ClientCertificate,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [int] $RequestTimeout = 30,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [switch] $SkipCertificateCheck
    )
    
    # Build the fully qualified URL based on the requested authentication method.
    $_targetURL = Join-Url -Path $baseURL -ChildPath $AUTHURLS[$AuthMethod]["URL"]

    # Get the CyberArk Authentication Token based on the Authentication Method.
    switch ($AuthMethod.ToUpper())
    {
        CYBERARK
        {
            if ($Credential)
            {
                # Call the function Get-AuthToken-CyberArk
                $_authPayload = @{
                    TargetURL = $_targetURL
                    Credential = $Credential
                    RequestTimeout = $RequestTimeout
                    SkipCertificateCheck = $SkipCertificateCheck.IsPresent
                }
                $_result = Get-AuthToken-CyberArk @_authPayload
            }
            else
            {
                Stop-Exit -Code 30 -Message "No Credential Provided!"
            }
            
        }
        LDAP
        {
            if ($Credential)
            {
                # Call the function Get-AuthToken-LDAP
                $_authPayload = @{
                    TargetURL = $_targetURL
                    Credential = $Credential
                    RequestTimeout = $RequestTimeout
                    SkipCertificateCheck = $SkipCertificateCheck.IsPresent
                }
                $_result = Get-AuthToken-LDAP @_authPayload
            }
            else
            {
                Stop-Exit -Code 31 -Message ("No Credential Provided!  Auth Method:  {0}" -f $AuthMethod)
            }
        }
        SAML
        {
            # Test the result.
            if ($true)
            {
                # Call the function Get-AuthToken-SAML
                $_authPayload = @{
                    TargetURL = $_targetURL
                    RequestTimeout = $RequestTimeout
                    SkipCertificateCheck = $SkipCertificateCheck.IsPresent
                }
                #$_result = Get-AuthToken-SAML @_authPayload
                $_result = Get-AuthToken-SAML-Brute @_authPayload
            }
            else
            {
                Stop-Exit -Code 32 -Message ("Failed to retrieve the IDP URL!  Auth Method:  {0}" -f $AuthMethod)
            }
        }
        RADIUS
        {
            Stop-Exit -Code 33 -Message ("Auth Method Not Implemented!  Auth Method:  {0}" -f $AuthMethod)
            if ($Credential)
            {
                # Call the function Get-AuthToken-RADIUS
                $_authPayload = @{
                    TargetURL = $_targetURL
                    Credential = $Credential
                    RequestTimeout = $RequestTimeout
                    SkipCertificateCheck = $SkipCertificateCheck.IsPresent
                }
                $_result = Get-AuthToken-RADIUS @_authPayload
            }
            else
            {
                Stop-Exit -Code 33 -Message ("No Credential Provided!  Auth Method:  {0}" -f $AuthMethod)
            }
        }
        PKI
        {
            if ($userClientCertificate)
            {
                # Call the function Get-AuthToken-PKI
                $_authPayload = @{
                    TargetURL = $_targetURL
                    Certificate = $ClientCertificate
                    RequestTimeout = $RequestTimeout
                    SkipCertificateCheck = $SkipCertificateCheck.IsPresent
                }
                $_result = Get-AuthToken-PKI @_authPayload
            }
            else
            {
                Stop-Exit -Code 34 -Message ("No Certificate Provided!  Auth Method:  {0}" -f $AuthMethod)
            }
        }
        PKIPN
        {
            if ($userClientCertificate)
            {
                # Call the function Get-AuthToken-PKI
                $_authPayload = @{
                    TargetURL = $_targetURL
                    Certificate = $ClientCertificate
                    RequestTimeout = $RequestTimeout
                    SkipCertificateCheck = $SkipCertificateCheck.IsPresent
                }
                $_result = Get-AuthToken-PKIPN @_authPayload
            }
            else
            {
                Stop-Exit -Code 35 -Message ("No Certificate Provided!  Auth Method:  {0}" -f $AuthMethod)
            }
        }

    }
    # Process the authentication token result.
    if (($_result) -and ($_result -ne ""))
    {
        # The result is not null and it is not an empty string.
        #  Convert the result from JSON to a string.
        $_authToken = $_result

        Write-Verbose ("{0} : Authentication Token:  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_authToken)

        return $_authToken
    }

    # Return the authentication token.
    return $_result
}

function Get-AuthToken-CyberArk
{
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $TargetURL,

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [pscredential] $Credential,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [switch] $SkipCertificateCheck,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [int] $RequestTimeout = 30
    )
    # Build the body.
    $_requestBody = @{
        "username" = $Credential.UserName
        "password" = $Credential.GetNetworkCredential().Password
    }
    # Build the hash table to hold the web request properties.
    $_requestAttributes = @{
        URI = $TargetURL
        Method = "Post"
        SessionVariable = "WebSession"
        #Headers = $_Headers
		Body 	= ($_requestBody | ConvertTo-Json)
        SkipCertificateCheck = $SkipCertificateCheck.IsPresent
    }
    
    $_result = Invoke-PASRestMethod @_requestAttributes
    
    return $_result
    
}
function Get-AuthToken-LDAP
{
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $TargetURL,

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [pscredential] $Credential,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [switch] $SkipCertificateCheck,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [int] $RequestTimeout = 30
    )
    #
    # Build the body.
    $_requestBody = @{
        "username" = $Credential.UserName
        "password" = $Credential.GetNetworkCredential().Password
    }
    # Build the hash table to hold the web request properties.
    $_requestAttributes = @{
        URI = $TargetURL
        Method = "Post"
        SessionVariable = "WebSession"
        #Headers = $_Headers
		Body 	= ($_requestBody | ConvertTo-Json)
        SkipCertificateCheck = $SkipCertificateCheck.IsPresent
    }
    
    $_result = Invoke-PASRestMethod @_requestAttributes

    return $_result
}
function Get-AuthToken-SAML
{
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $TargetURL,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [switch] $SkipCertificateCheck,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [int] $RequestTimeout = 30
    )

    <#  This section isn't working.
        Always getting the IDP URL.  Like the web session isn't being passed.
    #>
    # Get the URL for the iDP.
    $_idpRequest = @{
        TargetURL = $TargetURL
        SkipCertificateCheck = $SkipCertificateCheck.IsPresent
        RequestTimeout = $RequestTimeout
    }
    $_idpURL = Get-IdpURL @_idpRequest

    # Save the IDP Web Request Session
    $_idpSession = $_idpURL[1]

    # Output information about the returned web session.
    if ($_idpSession)
    {
        # An existing web session was passed.
        Write-Verbose ("{0} :  Web Session Headers :  `r`n{1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), ($_idpSession.Headers | ConvertTo-Json))

        # Get the cookies from the container.
        $_selectedCookies = $_idpSession.Cookies.GetCookies($TargetURL)

        # Output the cookies.
        Write-Verbose ("{0} :  Web Session Cookies :  `r`n`t{1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), ($_selectedCookies -join "`r`n`t"))
    }

    # Get the SAML response.
    $_samlResponse = Get-SamlResponseEXE -TargetURL $_idpURL[0]
    
    # Get the Auth Token.
    # Build the Headers.
    $_requestHeaders = @{
        'Accept' = 'application/json'
    }

    # Build the body.
    $_requestBody = @{
        'SAMLResponse' = $_samlResponse;
        'apiUse' = $true;
        'concurrentSession' = $true
    }

    # Build the hash table to hold the web request properties.
    $_requestAttributes = @{
        URI = $TargetURL
        Method = "Post"
        Headers = $_requestHeaders
		Body 	= ($_requestBody | ConvertTo-Json)
        SkipCertificateCheck = $SkipCertificateCheck.IsPresent
        WebSession = $_idpSession
        ContentType = "application/x-www-form-urlencoded"
    }
    
    $_result = Invoke-PASRestMethod @_requestAttributes 
    
    # Test the result.
    if ($_result -ilike "http*")
    {
        # The authentication token shouldn't contain a url.
        Stop-Exit -Code 33 -Message ("Invalid authentication token received!  `r`n`tReceived:  {0}" -f $_result)
    }
    else
    {
        return $_result
    }
}
function Get-AuthToken-SAML-Brute
{
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $TargetURL,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [switch] $SkipCertificateCheck,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [int] $RequestTimeout = 30
    )

    ### Get the IDP URL ###
    # Build the web request options.
    $idpWebRequestOptions = @{
        UseBasicParsing = $null
        Uri = $TargetURL
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
        Write-Host ("Getting IDP URL from:  {0}" -f $TargetURL)
        $idpResult = Invoke-WebRequest @idpWebRequestOptions
        Write-Verbose ("IDP URL:  {0}" -f $idpResult)
    }
    catch
    {
        Write-Warning ("Failed to get IDP URL from:  {0}" -f $TargetURL)
        Write-Warning ("IDP Result:  {0}" -f $idpResult)
        Write-Warning $_
        Exit $LASTEXITCODE
    }

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

    # Build the web request options.
    $atWebRequestOptions = @{
        UseBasicParsing = $null
        Uri = $TargetURL
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
        Write-Host ("Getting CyberArk Auth Token from:  {0}" -f $TargetURL)
        $atResult = Invoke-WebRequest @atWebRequestOptions
    }
    catch
    {
        Write-Warning ("Failed to retrieve Auth Token from:  {0}" -f $TargetURL)
        Write-Warning ("Auth Token Result:  {0}" -f $atResult)
        Write-Warning $_
        Exit $LASTEXITCODE
    }

    # Test the result.
    if ($atResult -ilike "http*")
    {
        # The authentication token shouldn't contain a url.
        Stop-Exit -Code 33 -Message ("Invalid authentication token received!  `r`n`tReceived:  {0}" -f $_result)
    }
    else
    {
        # Save the web session if it exists.
        if ($idpSession)
        {
            $script:WebSession = $idpSession
        }

        # Convert the result into JSON.
        $atJSON = ConvertFrom-Json $atResult

        Write-Verbose ("Auth Token:  {0}" -f $atJSON)
        return $atJSON
    }
}
function Get-AuthToken-RADIUS
{
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $TargetURL,

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [pscredential] $Credential,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [switch] $SkipCertificateCheck,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [int] $RequestTimeout = 30
    )
    #
}
function Get-AuthToken-PKI
{
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $TargetURL,

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [switch] $SkipCertificateCheck,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [int] $RequestTimeout = 30
    )
    # Build the hash table to hold the web request properties.
    $_requestAttributes = @{
        URI = $TargetURL
        Method = "Post"
        SessionVariable = "WebSession"
        #Headers = $_Headers
		#Body 	= ($_body | ConvertTo-Json)
        Certificate = $Certificate
        SkipCertificateCheck = $SkipCertificateCheck.IsPresent
    }

    $_result = Invoke-PASRestMethod @_requestAttributes
    
    # Return the result which should be the Authentication Token.
    return $_result
}
function Get-AuthToken-PKIPN
{
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $TargetURL,

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [switch] $SkipCertificateCheck,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [int] $RequestTimeout = 30
    )
    # Build the hash table to hold the web request properties.
    $_requestAttributes = @{
        URI = $TargetURL
        Method = "Post"
        SessionVariable = "WebSession"
        #Headers = $_Headers
		#Body 	= ($_body | ConvertTo-Json)
        Certificate = $Certificate
        SkipCertificateCheck = $SkipCertificateCheck.IsPresent
    }

    $_result = Invoke-PASRestMethod @_requestAttributes
    
    return $_result
}
function Revoke-AuthToken
{
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $TargetURL,

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $AuthToken,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [switch] $SkipCertificateCheck,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [int] $RequestTimeout = 30
    )
    # Create the fully qualified URL.
    $_targetURL = Join-Url -Path $TargetURL -ChildPath $AUTHURLS["Logoff"]["URL"]

    # Build the hash table to hold the web request properties.
    $_requestAttributes = @{
        URI = $_targetURL
        Method = "Post"
        WebSession = $WebSession
        #Headers = $_Headers
		#Body 	= ($_body | ConvertTo-Json)
    }

    if ($SkipCertificateCheck)
	{
		$_requestAttributes['SkipCertificateCheck'] = $true
	}
    
    $_result = Invoke-PASRestMethod @_requestAttributes

    return $_result
}
#endRegion Get Authentication Token

##########################################################
#region CyberArk Account Functions
##########################################################
function Get-Accounts
{
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $BaseURL,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $Token,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $SearchText,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $SafeName,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
            [ValidateSet('Contains','StartsWith')]
        [string] $SearchType,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [int] $Limit,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [int] $OffSet
    )

    # Get the target URL.
    $_targetURL = $ACCOUNTSURLS["GetAccounts"]
    #/API/Accounts?search={search}&searchType={searchType}&sort={sort}&offset={offset}&limit={limit}&filter={filter}/

    $_urlOptions = @{
        "search" = $SearchText
        "searchType" = $SearchType
        "sort" = ""
        "offset" = $OffSet
        "limit" = $Limit
        "filter" = ""
    }

    # Check to see if a safename was specified.
    if ($SafeName -ne "")
    {
        # Update the filter statement.
        $_urlOptions["filter"] = ("safename eq {0}" -f $SafeName)
    }
    
    # Split the URL from the Query.
    $_urlBase = $_targetURL.Split('?')

    # Split the URL so we can only use the attributes we have.
    $_urlQueryStubs = $_urlBase[1].Split('&')

    # Create the new URL stub to hold the values.
    $_newQueryStub = $_urlBase[0] + '?'

    #Get-QueryParameterString -BaseURI "" -QueryParameters ""
    # Loop over the query stubs and populate a new URL stub.
    foreach ($_stub in $_urlQueryStubs)
    {
        # Split the Key from the Value.
        $_key, $_value = $_stub.Split('=')

        # Check if we have a vlue for this key.
        if ($_urlOptions.$_key -ne "")
        {
            # Entry is not blank.
            Write-Verbose ("Key ({0}) : Value ({1})" -f $_key, $_urlOptions.$_key)
            $_newQueryStub += ("{0}={1}&" -f $_key, $_urlOptions.$_key)
        }
    }

    # Strip trailing ampersand '&'
    if ($_newQueryStub.Substring(($_newQueryStub.Length -1), 1) -eq "&")
    {
        $_newQueryStub = $_newQueryStub.Substring(0, ($_newQueryStub.Length -1))
    }

    Write-Verbose ("New stub URL:  {0}" -f $_newQueryStub)
    
    # Build the hash table to hold the web request properties.
    $_requestAttributes = @{
        URI = (Join-Url -Path $BaseURL -ChildPath $_newQueryStub)
        Method = "Get"
        WebSession = $WebSession
        #Headers = $_Headers
        #Body 	= ($_body | ConvertTo-Json)
    }
    # Make the request.
    $_result = Invoke-PASRestMethod @_requestAttributes

    # Return the result
    return $_result
}

function Get-AccountSecret
{
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $BaseURL,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $Token,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $AccountID,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $Reason = "Test",

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $TicketingSystem,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $TicketID,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $Version,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
            [ValidateSet('Show','Copy','Connect')]
        [string] $ActionType = "Copy",

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $ConnectAddress

    )

    # Get the target URL.
    $_targetURL = $ACCOUNTACTIONSURLS["GetPasswordValue"]["URL"]
    #https://<IIS_Server_Ip>/PasswordVault/API/Accounts/{accountId}/Password/Retrieve/

    # Update the account ID in the URL.
    $_newQueryStub = $_targetURL.Replace("{accountId}", $AccountID)
    
    Write-Verbose ("New stub URL:  {0}" -f $_newQueryStub)
    
    # Build the Body
    $_body = @{
        ActionType = $ActionType
    }

    # Add Conditional Body elements.
    if (($null -ne $ConnectAddress) -and ($ConnectAddress -ne ""))
    {
        $_body.Add("Machine", $ConnectAddress)
        $_body.Add("isUse", $true)
    }
    if (($null -ne $TicketingSystem) -and ($TicketingSystem -ne ""))
    {
        $_body.Add("TicketingSystemName", $TicketingSystem)
        $_body.Add("TicketId", $TicketID)
    }
    if (($null -ne $Version) -and ($Version -ne ""))
    {
        $_body.Add("Version", $Version)
    }
    if (($null -ne $Reason) -and ($Reason -ne ""))
    {
        $_body.Add("Reason", $Reason)
    }

    # Build the hash table to hold the web request properties.
    $_requestAttributes = @{
        URI = (Join-Url -Path $BaseURL -ChildPath $_newQueryStub)
        Method = $ACCOUNTACTIONSURLS["GetPasswordValue"]["Method"]
        WebSession = $WebSession
        #Headers = $_Headers
        Body 	= ($_body | ConvertTo-Json)
    }
    # Make the request.
    $_result = Invoke-PASRestMethod @_requestAttributes

    # Convert JSON.
    $_decodedResult = $_result | ConvertFrom-Json

    # Return the result
    return $_decodedResult
}
#endRegion CyberArk Account Functions

##########################################################
#region CyberArk Safe Functions
##########################################################
function Add-Safe
{
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $BaseURL,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $Token
    )
    #
}
function Update-Safe
{
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $BaseURL,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $Token
    )
    #
}
function Get-AllSafes
{
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $BaseURL,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $Token,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $SafeName,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [int] $Offset,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [int] $Limit,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $Sort,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [switch] $IncludeAccounts,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [bool] $ExtendedDetails = $true
    )
    # 	https://localhost/PasswordVault/api/safes?includeAccounts=true&offset=8&limit=4/

    # Get the URL Stub and Method
    $_urlStubMethod = $SAFEURLS["GetAllSafes"]
    
    # Get the URL Stub.
    $_urlStub = $_urlStubMethod["URL"]

    # Get the Method.
    $_method = $_urlStubMethod["Method"]

    # Build hash table to hold query options.
    $_queryOptions = @{
        includeAccounts = $false
        extendedDetails = $false
    }

    # Test the provided query options and add them to the hash table if not null or blank.
    if (($null -ne $Offset) -and ($Offset -gt 0))
    {
        $_queryOptions.Add("Offset", $Offset)
    }
    if (($null -ne $Limit) -and ($Limit -gt 0))
    {
        $_queryOptions.Add("Limit", $Limit)
    }
    if (($null -ne $Sort) -and ($Sort -ne ""))
    {
        $_queryOptions.Add("Sort", $Sort)
    }
    if ($IncludeAccounts)
    {
        $_queryOptions.IncludeAccounts = $true
    }
    if ($ExtendedDetails)
    {
        $_queryOptions.ExtendedDetails = $ExtendedDetails
    }

    # Build the stub URL with Query.
    $_newQueryStub = Get-QueryParameterString -BaseURI $_urlStub -QueryParameters $_queryOptions

    # It is possible to have a loarge number of items returned.  Use a Do While loop.
    do
    {
        # Build the hash table to hold the web request properties.
        $_requestAttributes = @{
            URI = (Join-Url -Path $BaseURL -ChildPath $_newQueryStub)
            Method = $_method
            WebSession = $WebSession
        }

        # Make the request.
        $_result = Invoke-PASRestMethod @_requestAttributes

        # Get the first set of results.
        $_values += $_result.Value

        # Get the next link string.
        $_newQueryStub = $_result.NextLink

    } while ($null -ne $_newQueryStub)
    
    # Return the result
    return $_values

}
function Get-SafeDetails
{
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $BaseURL,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $Token,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $SafeUrlId,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [switch] $IncludeAccounts
    )
    # https://<IIS_Server_Ip>/PasswordVault/API/Safes/{SafeUrlId}/

    # Get the URL Stub and Method
    $_urlStubMethod = $SAFEURLS["GetSafeDetails"]
    
    # Get the URL Stub.
    $_urlStub = $_urlStubMethod["URL"]

    # Get the Method.
    $_method = $_urlStubMethod["Method"]

    # Replace the SafeUrlId.
    $_urlStub = $_urlStub.Replace("{SafeUrlId}", $SafeUrlId)

    # Build hash table to hold query options.
    $_queryOptions = @{
        includeAccounts = $false
    }

    # Test the provided query options and add them to the hash table if not null or blank.
    if ($IncludeAccounts)
    {
        $_queryOptions.IncludeAccounts = $true
    }

    # Build the stub URL with Query.
    $_newQueryStub = Get-QueryParameterString -BaseURI $_urlStub -QueryParameters $_queryOptions

    # Build the hash table to hold the web request properties.
    $_requestAttributes = @{
        URI = (Join-Url -Path $BaseURL -ChildPath $_newQueryStub)
        Method = $_method
        WebSession = $WebSession
    }

    # Make the request.
    $_result = Invoke-PASRestMethod @_requestAttributes

    # Return the result.
    return $_result
}
function Get-SafesByPlatformID
{
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $BaseURL,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $Token
    )
    #
}
function Get-AllSafeMembers
{
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $BaseURL,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $Token,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $SafeUrlId,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string[]] $Filter
    )
    # https://<IIS_Server_Ip>/PasswordVault/API/Safes/{SafeUrlId}/Members/

    # Get the URL Stub and Method
    $_urlStubMethod = $SAFEMEMBERSURLS["GetAllSafeMembers"]
    
    # Get the URL Stub.
    $_urlStub = $_urlStubMethod["URL"]

    # Get the Method.
    $_method = $_urlStubMethod["Method"]

    # Replace the SafeUrlId.
    $_urlStub = $_urlStub.Replace("{SafeUrlId}", $SafeUrlId)

    # Build hash table to hold query options.
    $_queryOptions = @{
        includeAccounts = $false
    }

    # Test the provided query options and add them to the hash table if not null or blank.
    if ($IncludeAccounts)
    {
        $_queryOptions.IncludeAccounts = $true
    }

    # Build the stub URL with Query.
    $_newQueryStub = Get-QueryParameterString -BaseURI $_urlStub -QueryParameters $_queryOptions

    # Append any query filters.
    # Test if any Filters are requested.
    if (($null -ne $Filter) -and ($Filter[0] -ne ""))
    {
        # Call the Query Filter helper
        $_newQueryStub = Get-QueryFilterString -BaseURI $_urlStub -QueryFilters $Filter
    }

    # It is possible to have a loarge number of items returned.  Use a Do While loop.
    do
    {
        # Build the hash table to hold the web request properties.
        $_requestAttributes = @{
            URI = (Join-Url -Path $BaseURL -ChildPath $_newQueryStub)
            Method = $_method
            WebSession = $WebSession
        }

        # Make the request.
        $_result = Invoke-PASRestMethod @_requestAttributes

        # Get the first set of results.
        $_values += $_result.Value

        # Get the next link string.
        $_newQueryStub = $_result.NextLink

    } while ($null -ne $_newQueryStub)
    
    # Return the result
    return $_values
    
}
function Get-SafeMember
{
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $BaseURL,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $Token,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $SafeUrlId,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $MemberName
    )
    # https://<IIS_Server_Ip>/PasswordVault/API/Safes/{SafeUrlId}/Members/{MemberName}/

    # Get the URL Stub and Method
    $_urlStubMethod = $SAFEMEMBERSURLS["GetSafeMember"]
    
    # Get the URL Stub.
    $_urlStub = $_urlStubMethod["URL"]

    # Get the Method.
    $_method = $_urlStubMethod["Method"]

    # Replace the SafeUrlId.
    $_urlStub = $_urlStub.Replace("{SafeUrlId}", $SafeUrlId)

    # Replace the MemberName.
    $_urlStub = $_urlStub.Replace("{MemberName}", $MemberName)

    # Build the hash table to hold the web request properties.
    $_requestAttributes = @{
        URI = (Join-Url -Path $BaseURL -ChildPath $_urlStub)
        Method = $_method
        WebSession = $WebSession
    }

    # Make the request.
    $_result = Invoke-PASRestMethod @_requestAttributes

    # Get the first set of results.
    $_values += $_result.Value

    # Return the result
    return $_values
}
function Add-SafeMember
{
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $BaseURL,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $Token,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $SafeUrlId,

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $MemberName,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $SearchIn,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
            [ValidateSet("User", "Group")]
        [string] $MemberType,

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [psobject] $Permissions,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [datetime] $ExpirationDate
    )
    # https://<IIS_Server_Ip>/PasswordVault/API/Safes/{safeUrlId}/Members/

    $_resultSuccess = $false

    # Get the URL Stub and Method
    $_urlStubMethod = $SAFEMEMBERSURLS["AddSafeMember"]
    
    # Get the URL Stub.
    $_urlStub = $_urlStubMethod["URL"]

    # Get the Method.
    $_method = $_urlStubMethod["Method"]

    # Replace the SafeUrlId.
    $_urlStub = $_urlStub.Replace("{SafeUrlId}", $SafeUrlId)

    # Build the body.
    $_body = @{
        memberName = $MemberName
        permissions = $Permissions
    }

    # Add additional body attributes if not blank of null.
    if (($null -ne $MemberType) -and ($MemberType -ne ""))
    {
        $_body.Add("memberType", $MemberType)
    }
    if (($null -ne $searchIn) -and ($SearchIn -ne ""))
    {
        $_body.Add("searchIn", $SearchIn)
    }
    if (($null -ne $ExpirationDate) -and ($ExpirationDate -ne ""))
    {
        $_body.Add("membershipExpirationDate", (New-TimeSpan -Start (Get-Date "01/01/1970") -End ($ExpirationDate)).TotalSeconds)
    }
    
    # Build the hash table to hold the web request properties.
    $_requestAttributes = @{
        URI = (Join-Url -Path $BaseURL -ChildPath $_urlStub)
        Method = $_method
        WebSession = $WebSession
        Body = ($_body | ConvertTo-Json)
    }

    # Output Status.
    Write-Verbose ("{0} :  Adding  : Safe URL ID ({1}) : Member Type ({2}) : Member Name ({3}) : `r`n`tPermissions:  `r`n`t`t{4}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $SafeUrlId, $MemberType, $MemberName, ($Permissions -join "`r`n`t`t"))

    # Make the request.
    $_result = Invoke-PASRestMethod @_requestAttributes

    # Test the result.
    if (($null -ne $_result) -and ($_result -ne ""))
    {
        # Result has a value.
        if ($_result.memberName -ieq $MemberName)
        {
            $_resultSuccess = $true
        }
    }
    
    # Return the result
    return $_resultSuccess
}
function Update-SafeMember
{
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $BaseURL,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $Token,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $SafeUrlId,

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $MemberName,
        
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [psobject] $Permissions,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [datetime] $ExpirationDate
    )
    # https://<IIS_Server_Ip>/PasswordVault/API/Safes/{SafeUrlId}/Members/{MemberName}/

    # Get the URL Stub and Method
    $_urlStubMethod = $SAFEMEMBERSURLS["UpdateSafeMember"]
    
    # Get the URL Stub.
    $_urlStub = $_urlStubMethod["URL"]

    # Get the Method.
    $_method = $_urlStubMethod["Method"]

    # Replace the SafeUrlId.
    $_urlStub = $_urlStub.Replace("{SafeUrlId}", $SafeUrlId)

    # Replace the SafeUrlId.
    $_urlStub = $_urlStub.Replace("{MemberName}", $MemberName)

    # Build the body.
    $_body = @{
        memberName = $MemberName
        permissions = $Permissions
    }

    # Add additional body attributes if not blank of null.
    if (($null -ne $MemberType) -and ($MemberType -ne ""))
    {
        $_body.Add("memberType", $MemberType)
    }
    if (($null -ne $searchIn) -and ($SearchIn -ne ""))
    {
        $_body.Add("searchIn", $SearchIn)
    }
    if (($null -ne $ExpirationDate) -and ($ExpirationDate -ne ""))
    {
        $_body.Add("membershipExpirationDate", (New-TimeSpan -Start (Get-Date "01/01/1970") -End ($ExpirationDate)).TotalSeconds)
    }
    
    # Build the hash table to hold the web request properties.
    $_requestAttributes = @{
        URI = (Join-Url -Path $BaseURL -ChildPath $_urlStub)
        Method = $_method
        WebSession = $WebSession
        Body = ($_body | ConvertTo-Json)
    }

    # Output Status.
    Write-Verbose ("{0} : Updating : Safe URL ID ({1}) : Member Name ({2}) : `r`n`tPermissions:  `r`n`t`t{3}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $SafeUrlId, $MemberName, ($Permissions -join "`r`n`t`t"))

    # Make the request.
    $_result = Invoke-PASRestMethod @_requestAttributes

    # Test the result.
    if (($null -ne $_result) -and ($_result -ne ""))
    {
        # Result has a value.
        if ($_result.memberName -ieq $MemberName)
        {
            $_resultSuccess = $true
        }
    }
    
    # Return the result
    return $_resultSuccess
}
function Remove-SafeMember
{
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $BaseURL,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $Token,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $SafeUrlId,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $MemberName
    )
    # https://<IIS_Server_Ip>/PasswordVault/API/Safes/{SafeUrlId}/Members/{MemberName}/

    # Get the URL Stub and Method
    $_urlStubMethod = $SAFEMEMBERSURLS["DeleteSafeMember"]
    
    # Get the URL Stub.
    $_urlStub = $_urlStubMethod["URL"]

    # Get the Method.
    $_method = $_urlStubMethod["Method"]

    # Replace the SafeUrlId.
    $_urlStub = $_urlStub.Replace("{SafeUrlId}", $SafeUrlId)

    # Replace the MemberName.
    $_urlStub = $_urlStub.Replace("{MemberName}", $MemberName)

    $_resultSuccess = $false

    # Write Status.
    Write-Verbose ("{0} : Removing : Safe URL ID ({1}) : Member Name ({2})" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $SafeUrlId, $MemberName)

    # Build the hash table to hold the web request properties.
    $_requestAttributes = @{
        URI = (Join-Url -Path $BaseURL -ChildPath $_urlStub)
        Method = $_method
        WebSession = $WebSession
    }

    # Make the request.
    $_result = Invoke-PASRestMethod @_requestAttributes

    # Return the result
    return $true
}

#endRegion CyberArk Safe Functions

##########################################################
#region Process Functions
##########################################################
function Register-Authentication
{
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $AuthMethod,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [pscredential] $Credential,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $ThumbPrint
    )
    # Call the Test-AuthMethodReq function to verify the required credentials for the auth type.
    #  This function will ask for a credential or a client certificate if none was specified.
    $Creds = Test-AuthMethodReq -AuthMethod $AuthMethod -Credential $Credential -ThumbPrint $ThumbPrint

    # Validate the credentials returned from the Test-AuthMethodReq function and get the Authorization token.
    if ($Creds.Valid)
    {
        #
        if ($Creds.Type -ieq "Thumbprint")
        {
            # Pull the certificate from the value field.
            $userClientCertificate = $Creds.Value

            # Write a message
            Write-Host ("{0} : A client certificate was selected!  Thumbprint:  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $userClientCertificate.Thumbprint)

            Write-Host ("{0} : Using Certificate of:  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $userClientCertificate.SubjectName.Name)

            $_getAuthToken = @{
                BaseURL = $_baseURL
                AuthMethod = $AuthMethod
                ClientCertificate = $userClientCertificate
                RequestTimeout = $RequestTimeout
                SkipCertificateCheck = $SkipCertificateCheck.IsPresent
            }
            $_authToken = Get-AuthToken @_getAuthToken
        }
        elseif ($Creds.Type -ieq "Credential")
        {
            # Pull the credential from the value field.
            $Credential = $Creds.Value

            # Write a message
            Write-Host ("{0} : A user credential was selected!  Username:  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Credential.UserName)

            Write-Host ("{0} : Using Credential for:  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Credential.UserName)
        
            $_getAuthToken = @{
                BaseURL = $_baseURL
                AuthMethod = $AuthMethod
                Credential = $Credential
                RequestTimeout = $RequestTimeout
                SkipCertificateCheck = $SkipCertificateCheck.IsPresent
            }
            $_authToken = Get-AuthToken @_getAuthToken
        }
        elseif ($Creds.Type -ieq "None")
        {
            # Write a message
            Write-Host ("{0} : SAML authentication has been specified!" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))

            #  The certificate variable is not null.  Using certificate.
            Write-Host ("{0} : Using SAML Authentication." -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))

            $_getAuthToken = @{
                BaseURL = $_baseURL
                AuthMethod = $AuthMethod
                RequestTimeout = $RequestTimeout
                SkipCertificateCheck = $SkipCertificateCheck.IsPresent
            }
            $_authToken = Get-AuthToken @_getAuthToken
        }
        else
        {
            Stop-Exit -Code 12 -Message "An unknown state has been encountered when checking for the Credential and or ThumbPrint!"
        }
    }
    else
    {
        # Failed to provide or get the required credentials for the specified authentication method.
        if (($Credential) -and ($ThumbPrint))
        {
            Stop-Exit -Code 10 -Message ("A Credential and a ThumbPrint have been specified.`r`n`tOnly one can be specified!")
        }
        elseif ((!$Credential) -and (!$ThumbPrint))
        {
            Stop-Exit -Code 11 -Message ("{0} : No Credential or ThumbPrint has been specified!`r`n`tPlease specify at least one!" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
        }
        else
        {
            Stop-Exit -Code 12 -Message "An unknown state has been encountered when checking for the Credential and or ThumbPrint!"
        }
    }

    # Check if the authentication token was retrieved.
    if ((!$_authToken) -or ($_authToken -eq ""))
    {
        # No token retrieved!  Exit
        Stop-Exit -Code 4000 -Message ("Failed to retrieve authentication token!")
    }

    return $_authToken
}

function Import-SafePermissions
{
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string[]] $Files,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $BaseURL,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $AuthToken
    )
    # Create a variable to hold all safe names and URL IDs.
    $_allSafes = $null

    # Check if the Safe list has been pulled.
    if ($null -eq $_allSafes)
    {
        Write-Host ("{0} : Getting All Safe Names and URL IDs." -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
        # Build the hash table to hold the web request properties.
        $_requestAttributes = @{
            BaseURL = $BaseURL
        }
        
        # Get the template safe URL ID.
        $_allSafes = Get-AllSafes @_requestAttributes
    }

    # Create a variable to hold the template safe properties, and member permissions.
    $_templateSafe = $null
    $_templateSafeMembers = $null
    $_templateSafeRoleMembers = $null

    # Check to see if the template safe has been retrieved.
    if ($null -eq $_templateSafe)
    {
        # Get the template safe URL ID.
        $_templateURLID = ($_allSafes | Where-Object {$_.SafeName -ieq $TemplateSafe}).SafeUrlId

        Write-Host ("{0} : Getting template safe details.  Safe:  Name ({1}) URL ID ({2})" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $TemplateSafe, $_templateURLID)

        # Specify the request details.
        $_requestAttributes = @{
            BaseURL = $BaseURL
            SafeUrlId = $_templateURLID
        }

        # Make the call to get the safe details.
        $_templateSafe = Get-SafeDetails @_requestAttributes

        Write-Host ("{0} : Getting template safe owners." -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
        # Make the call to get the safe members.
        $_templateSafeMembers = Get-AllSafeMembers @_requestAttributes -Filter @("memberType eq group", "includePredefinedUsers eq False")
        
        # Filter the safe members to only include Role Groups.
        $_templateSafeRoleMembers = $_templateSafeMembers | Where-Object {$_.memberName -ilike ("{0}*" -f $RoleNamePrefix)}

    }

    # Loop over the passed in files
    foreach ($_file in $Files)
    {
        Write-Host ("{0} : Reading input file:  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_file)

        # Read the CSV file.
        $_uifCSV = Import-Csv -Path $_file

        # Track the loop count.
        $_csvLoopCount = 0

        # Loop over the CSV file.
        foreach ($_line in $_uifCSV)
        {
            # Increment the loop count.
            $_csvLoopCount++

            # Build the Domain\User
            if ($_line.Domain -eq "")
            {
                $domainUserName = $_line.UserName
            }
            else
            {
                $domainUserName = ("{0}\{1}" -f $_line.Domain, $_line.UserName)
            }
            # Write status line
            Write-Host ("{0} : Row ({1:d4}):  Safe ({2}) : User ({3}) : Action ({4}) : Role ({5})" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_csvLoopCount, $_line.SafeName, $domainUserName, $_line.Action, $_line.Role)

            # Get the SafeUrlId from All Safes.
            $_targetSafe = ($_allSafes | Where-Object {$_.SafeName -ieq $_line.SafeName}).SafeUrlId

            # Get the current safe members for target safe.
            $_requestAttributes = @{
                BaseURL = $BaseURL
                SafeUrlId = $_targetSafe
            }
            $_targetSafeMembers = Get-AllSafeMembers @_requestAttributes -Filter @("includePredefinedUsers eq False")

            # Check if the requested member is already in the safe owners list.
            $_targetUserAlreadymember = $_targetSafeMembers | Where-Object {$_.memberName -ieq $_line.Username}

            # Set the target safe, user, and permission attributes.
            $_requestAttributes = @{
                BaseURL = $BaseURL
                SafeUrlId = $_targetSafe
                MemberName = $_line.Username
                MemberType = $_line.UserType
                SearchIn = $_line.Domain
            }

            # Get the permissions if the action is not Delete / Remove.
            if (($_line.Action -ine "Remove") -and ($_line.Action -ine "Delete"))
            {
                Write-Verbose ("{0} : Getting Role Permissions :  Safe ({1})  Role Name ({2})" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_templateSafe.safeName, $_line.Role)
                $_targetRolePermissions = ($_templateSafeRoleMembers | Where-Object {$_.memberName -ieq $_line.Role}).Permissions

                # Check if permissions were retrieved.
                if (($null -ne $_targetRolePermissions) -and ($_targetRolePermissions -ne ""))
                {
                    # Add the permissions to the request attributes.
                    $_requestAttributes.Add("Permissions", $_targetRolePermissions)

                    # Check the action to be performed.
                    if (($_line.Action -ieq "Add") -and ($null -eq $_targetUserAlreadymember))
                    {
                        # The user is NOT an owner of the safe.  Add.
                        $_actionResultSuccess = Add-SafeMember @_requestAttributes
                        $_messageAction = "Add"
                    }
                    elseif (($_line.Action -ieq "Add") -and ($null -ne $_targetUserAlreadymember))
                    {
                        # The user is an owner of the safe.  Update instead.
                        $_requestAttributes.Remove("SearchIn")
                        $_requestAttributes.Remove("MemberType")
                        $_actionResultSuccess = Update-SafeMember @_requestAttributes
                        $_messageAction = "Update"
                    }
                    elseif (($_line.Action -ieq "Update") -and ($null -eq $_targetUserAlreadymember))
                    {
                        # The user is NOT an owner of the safe.  Add instead.
                        $_actionResultSuccess = Add-SafeMember @_requestAttributes
                        $_messageAction = "Add"
                    }
                    elseif (($_line.Action -ieq "Update") -and ($null -ne $_targetUserAlreadymember))
                    {
                        # The user is an owner of the safe.  Update.
                        $_requestAttributes.Remove("SearchIn")
                        $_requestAttributes.Remove("MemberType")
                        $_actionResultSuccess = Update-SafeMember @_requestAttributes
                        $_messageAction = "Update"
                    }
                    else
                    {
                        # Unknown Action Requested.
                        $_actionResultSuccess = $false
                        $_messageAction = ("Unknown Action ({0})" -f $_line.Action)
                    }

                }
                else
                {
                    # Get role names in template safe permissions.
                    $_roleNamesOnTemplateSafeRaw = ($_templateSafeRoleMembers | Select-Object memberName).memberName

                    # Build Safe Member Names
                    $_roleNamesOnTemplateSafe = ($_roleNamesOnTemplateSafeRaw -join "`r`n`t`t`t")
                    
                    # Write warning.
                    Write-Warning ("{0} : Specified Role Permissions NOT found in template safe!  Safe ({1}) | Role Name ({2}) | `r`n`tValid Safe Role Groups: `r`n`t`t {3}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_templateSafe.safeName, $_line.Role, $_roleNamesOnTemplateSafe)

                    # The user is NOT an owner of the safe.  Add.
                    $_actionResultSuccess = $false
                    $_messageAction = "Role NOT Found!"
                }
                
            }
            else
            {
                if ((($_line.Action -ieq "Remove") -or ($_line.Action -ieq "Delete")) -and ($null -eq $_targetUserAlreadymember))
                {
                    # The user is NOT an owner of the safe.  Nothing to do.
                    $_actionResultSuccess = $false
                    $_messageAction = "Not a member!"
                }
                elseif ((($_line.Action -ieq "Remove") -or ($_line.Action -ieq "Delete")) -and ($null -ne $_targetUserAlreadymember))
                {
                    # Remove unneeded keys from request attributes.
                    $_requestAttributes.Remove("SearchIn")
                    $_requestAttributes.Remove("MemberType")

                    # The user is an owner of the safe.  Remove them.
                    $_actionResultSuccess = Remove-SafeMember @_requestAttributes
                    $_messageAction = "Remove/Delete"
                }
            }

            # Update CSV record with results.
            $_line | Add-Member -Name "Performed Action" -Type NoteProperty -Value $_messageAction
            $_line | Add-Member -Name "Action Success" -Type NoteProperty -Value $_actionResultSuccess

        }

        Write-Verbose ("{0} : Getting path of the input file:  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_file)

        # Determine if the variable $_file contains a relative or absolute path.
        if (![System.IO.Path]::IsPathRooted($_file))
        {
            # Path is relative.  Get full path.
            $_file = Resolve-Path -Path $_file

        }

        # Get the output folder path from the selected input file.
        $_outputFilePath = [System.IO.Path]::GetDirectoryName($_file)

        # Get the base filename from the selected input file.
        $_outputFileName = [System.IO.Path]::GetFileName($_file)

        # Build the new filename.
        $_newOutputFileName = ("{0}_OUT_{1}" -f (Get-Date -Format "yyyy-MM-dd_HHmmss"), $_outputFileName)

        # Build the full path and filename.
        $_outputFile = Join-Path -Path $_outputFilePath -ChildPath $_newOutputFileName

        # Write results to a new file.
        Write-Host ("{0} : Writing results to:  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_outputFile)
        $_uifCSV | Export-Csv -Path $_outputFile -NoTypeInformation

    }
}
#endRegion Process Functions

##########################################################
#region Flow
##########################################################
Write-Host "**********  Starting  **********"

# Build the base URL.  This joins the Base URI to the IIS Application Name.
$_baseURL = Join-Url -Path $PVWAURL -ChildPath $IISAppName

Write-Verbose ("{0} : Base URL:  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_baseURL)

##########################################################
#region Custom Code
##########################################################
Write-Host ("{0} : Asking for file(s)." -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))

# Get the input file(s).
if (($null -eq $InputFiles) -or ($InputFiles -eq ""))
{
    [array]$InputFiles = Get-InputFiles -StartLocation (Get-Location) -FileFilter "CSV files (*.csv)|*.csv"
}

# Check the input files again.
if (($null -eq $InputFiles) -or ($InputFiles -eq ""))
{
    # No files selected or passed in.  Exit with error.
    Stop-Exit -Code 30
}

Write-Host ("{0} : Getting Authentication Token from:  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_baseURL)

# Check the credential and prompt if it is null.
if ($null -eq $Credential)
{
    # Prompt the user for their credentials.
    $Credential = Get-Credential -Message "CyberArk API Credential Required!"
}

# Check to see if the user provided a credential.
if (($null -ne $Credential) -and ($Credential.Password.Length -gt 7))
{
    # Get the CyberArk Authentication Token.
    $CyberArkAuthToken = Register-Authentication -AuthMethod $AuthMethod -Credential $Credential -ThumbPrint $ThumbPrint
}
else
{
    # Write error and exit.
    Stop-Exit -Code 22
}

# Check the CyberArk Auth Token to see if it is present.
if (($null -ne $CyberArkAuthToken) -and ($CyberArkAuthToken -ne ""))
{
    # Call the Safe Permissions Function
    Import-SafePermissions -BaseURL $_baseURL -Files $InputFiles -AuthToken $CyberArkAuthToken
}
else
{
    # Write error and exit
    Stop-Exit -Code 21
}

#endRegion Custom Code

##########################################################
#region Logoff
##########################################################
Write-Host ("{0} : Entered Logoff Section." -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
# Test if there is an authentication token.
if ($CyberArkAuthToken)
{
    $_revokeAuthToken = @{
        TargetURL = $_baseURL
        AuthToken = $CyberArkAuthToken
        RequestTimeout = $RequestTimeout
    }
    $_result = Revoke-AuthToken @_revokeAuthToken
}
#endRegion Logoff
Write-Host "**********  Finished  **********"
#endRegion Flow