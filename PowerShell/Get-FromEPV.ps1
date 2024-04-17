<#
    .SYNOPSIS
    This script allows retrieving a credential, or MFA Cached SSH key.
    
    .DESCRIPTION
    This script will allow downloading a credential or an SSH key for 
    MFA caching.
    The CyberArk REST API is used with the authentication method specified.
    This script is written for PVWA version 12.2 or higher.
    This script requires PowerShell 5.1 or higher.
    If using SAML authentication then the getSAMLResponse exe is needed.
    
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

    .PARAMETER OutFile
    [string]:  This is a relative or fully qualified path for the output file.  Will be overwritten.
               For MFACache the specified file type will be used to choose the format.
               Valid formats:  PPK, PEM, OpenSSH -> myfile.ppk/myfile.pem/myfile.openssh

    .PARAMETER Action
    [string]:  This is the action to be taken.
               MFACache  :  This will download the SSH key for MFA caching.  Use with PSMP connections.
               Credential: This will download a credentials password and attributes.

    .PARAMETER Query
    [string]:  This is the query needed to identify the credential to be retrieved.
               -Query Safe=My Safe;Folder=root;Object=MyObject

    .OUTPUTS
    Output can be sent to standard out or to a file.

    .NOTES
    This script leverages the work of the following people.
        https://github.com/allynl93
        https://github.com/infamousjoeg
        https://github.com/pspete

    .LINK
    https://github.com/allynl93/getSAMLResponse-Interactive

    .LINK
    https://github.com/allynl93/getSAMLResponse-Interactive/releases
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
            [ValidateSet('CyberArk','LDAP','SAML','PKI','PKIPN')]
        [string] $AuthMethod = "PKIPN",
    
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [pscredential] $Credential,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $ThumbPrint = "61c2808e62b8b62784b4650e3f14112e29485842",
        # = "61c2808e62b8b62784b4650e3f14112e29485842",  My YubiKey Cert

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
        [string] $OutFile,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
            [ValidateSet('MFACache','Credential')]
        [string] $Action = "Credential",

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $Query = "Safe=PRS-TX-JMCWILLIAMS;Folder=Root;Object=nvidia.com-T1jmcwilliams"
    )

# Enable Verbose Logging :  
$VerbosePreference='Continue'
#$SkipCertificateCheck = $true
# Disable Verbose Logging:  $VerbosePreference='SilentlyContinue'

##########################################################
#region URL Stubs
##########################################################
# Authentication
$AUTHURLS = @{
    "CyberArk" = "/API/auth/cyberark/logon"
    "LDAP" = "/API/auth/ldap/logon"
    "SAML" = "/API/auth/saml/logon"
    "RADIUS" = "/API/auth/radius/logon"
    "PKI" = "/API/auth/pki/logon"
    "PKIPN" = "/API/auth/pkipn/logon"
    "LogOff" = "/API/auth/logoff"
}
# Safe
# Account
# User
# Group

#endRegion URLs

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
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $Message
    )
    # This will end script execution and exit.
    Write-Warning ("{0} : Exit Requested : Code ({1:d4}) : {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Code, $Message)

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

function Write-File
{
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $Path,

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $Data
    )

    # Write to the designated file.
    Out-File -FilePath $Path -InputObject $Data
}
#endRegion Helper Functions

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
            
            Write-Verbose ("{0} :   HTTP Request Body  :  `r`n{1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), ($PSBoundParameters.Body))
			
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

    # String to hold the value to be returned.
    $ReturnString = ""

    # Build the Query string
    $_QPString = ""
    foreach ($qpEnt in $_QueryParameters.Keys)
    {
        if ($_QPString -eq "")
        {
            $_QPString = ("?{0}={1}" -f $qpEnt, $_QueryParameters[$qpEnt])
        }
        else
        {
            $_QPString == ("&{0}={1}" -f $qpEnt, $_QueryParameters[$qpEnt])
        }
    }
    $ReturnString = $BaseURI + $_QPString

    return $ReturnString
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
        }
        else
        {
            # Ask the user for the credential.
            $_returnResult.Value = Get-Credential -Message ("Logon for {0}" -f $AuthMethod)

            # Verify that the credential is not null or empty.
            if (($_returnResult.Value) -and ($_returnResult.Value.Username -ne ""))
            {
                $_returnResult.Valid = $true
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
    $_targetURL = Join-Url -Path $baseURL -ChildPath $AUTHURLS[$AuthMethod]

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
    
    $_result = Invoke-PASRestMethod @_requestAttributes -Verbose
    
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
    
    $_result = Invoke-PASRestMethod @_requestAttributes -Verbose

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
    $_targetURL = Join-Url -Path $TargetURL -ChildPath $AUTHURLS["Logoff"]

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
#region CyberArk REST API:  MFA Caching
##########################################################
function Get-MFACaching
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
        [string] $Format,

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $Authorization
    )
    ### Get SSH Key ###
    # Build the URL
    $_targetURL = Join-Url -Path $BaseURL -ChildPath "API/Users/Secret/SSHKeys/Cache"

    # Build the Headers
    $_requestHeaders = @{
        'Accept' = 'application/json'
        'Authorization' = $Authorization
    }

    # Build the body
    $_requestBody = @{
        'formats' = @($Format)
    }

    # Build the web request options.
    $_requestAttributes = @{
        Uri = $_targetURL
        TimeoutSec = $RequestTimeout
        ContentType = "application/x-www-form-urlencoded"
        Method = "POST"
        Headers = $_requestHeaders
        Body = ($_requestBody|ConvertTo-Json)
        WebSession = $idpSession
    }

    $_result = Invoke-PASRestMethod @_requestAttributes

    return $_result
}

#endRegion CyberArk REST API:  MFA Caching

##########################################################
#region CyberArk REST API:  Accounts
##########################################################
function Get-Credential
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
        [string] $Query,

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $Authorization
    )
    # Split the query string.
    $_queryAttributes = $Query.Split(';')

    # Create a blank hash table to hold the query data.
    $_qAttribs = @{}

    # Decode the query string.
    foreach ($_qa in $_queryAttributes)
    {
        if ($_qa -ilike "Safe*")
        {
            $_qAttribs["Safe"] = ($_qa.Split('='))[1]
        }
        elseif ($_qa -ilike "Folder*")
        {
            $_qAttribs["Folder"] = ($_qa.Split('='))[1]
        }
        elseif ($_qa -ilike "Object*")
        {
            $_qAttribs["Object"] = ($_qa.Split('='))[1]
        }
        elseif ($_qa -ilike "VirtualUserName*")
        {
            $_qAttribs["VirtualUserName"] = ($_qa.Split('='))[1]
        }
        elseif ($_qa -ilike "Address*")
        {
            $_qAttribs["Address"] = ($_qa.Split('='))[1]
        }
        elseif ($_qa -ilike "Username*")
        {
            $_qAttribs["Username"] = ($_qa.Split('='))[1]
        }
        elseif ($_qa -ilike "LogonDomain*")
        {
            $_qAttribs["LogonDomain"] = ($_qa.Split('='))[1]
        }
    }
    
    # Output what was passed in.
    if ($_qAttribs.VirtualUserName)
    {
        Write-Host ("{0} : Getting account:  Safe ({1}) : Folder ({2}) : VirtualUsername ({3})" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_qAttribs.Safe, $_qAttribs.Folder, $_qAttribs.VirtualUsername)
    }
    elseif ($_qAttribs.Object)
    {
        Write-Host ("{0} : Getting account:  Safe ({1}) : Folder ({2}) : Object ({3})" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_qAttribs.Safe, $_qAttribs.Folder, $_qAttribs.Object)
    }
    else
    {
        Write-Warning ("No Object or VirtualUsername specified!")
        Stop-Exit -Code 4011 -Message "No Object or VirtualUsername specified!"
    }
    
    # Query CyberArk to get the account ID.

    # Build the Headers and Body
    $_requestHeaders = @{
        'Accept' = 'application/json'
        'Authorization' = $Authorization
    }

    # Set the Query and Filter attributes
    $filter = ("safename eq {0}" -f $_qAttribs.Safe)
    $search = ("{0}" -f $_qAttribs.Safe)

    # Only using the filter here.  The API search is limited.  Spaces work in the URL for this.
    $_requestURL = Join-Url -Path $BaseURL -ChildPath "/API/Accounts?filter=$($filter)"

    # Build the web request options.
    $_webRequestOptions = @{
        Uri = $_requestURL
        #TimeoutSec = $RequestTimeout
        ContentType = "application/json"
        Method = "GET"
        Headers = $_requestHeaders
        #WebSession = $idpSession
    }

    # Submit the request.  Return all accounts in the safe that meet the search criteria.
    $_result = Invoke-PASRestMethod @_webRequestOptions

    # Check if any results were returned.
    if ($_result)
    {
        # Filter the returned accounts for the Object name or the Virtual name.
        foreach ($_account in $_result.Value)
        {
            Write-Verbose ("{0} :         Account Name  :  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_account.name)
            Write-Verbose ("{0} :       Requested Name  :  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_qAttribs.Object)
            Write-Verbose ("{0} : Account Virtual Name  :  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_account.VirtualName)
            Write-Verbose ("{0} : Requested Virtual Name:  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_qAttribs.VirtualName)
            
            # Check if the account has a virtual name attribute.
            if (($_account.Name -ieq $_qAttribs.Object) -or ($_account.VirtualName -ieq $_qAttribs.VirtualUserName))
            {
                # Get the account content.
                
                Write-Host "********** Hi ***************"
            }
        }
    }
    
}

function Get-AccountContent
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
        [string] $AccountID,

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
            )]
        [string] $Authorization,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $Reason,

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
        [int] $Version,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
            [ValidateSet("Show", "Copy", "Connect")]
        [string] $ActionType,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [bool] $isUse,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
            )]
        [string] $Machine

    )

    # https://<IIS_Server_Ip>/PasswordVault/API/Accounts/{accountId}/Password/Retrieve/
    $_requestURL = Join-Url -Path $BaseURL -ChildPath ("/API/Accounts/{0}/Password/Retrieve/", $AccountID)

    # Build the request headers.
    $_requestHeaders = @{
        'Accept' = 'application/json'
        'Authorization' = $Authorization
    }

    # Build the request body.
    <# All available body options.
        {
            reason:"<Reason>",
            TicketingSystemName: "<Ticketing system>",
            TicketId: "<Ticketid>",
            Version: <version number>,
            ActionType: "<action type - show\copy\connect>,
            isUse: <true\false>,
            Machine: "<my remote machine address>"
        }
    #>
    $_requestBody = @{}

    # Populate the request body.
    if ($Reason)
    {$_requestBody["reason"] = $Reason}

    if ($TicketingSystem)
    {$_requestBody["TicketingSystemName"] = $TicketingSystem}

    if ($TicketID)
    {$_requestBody["TicketId"] = $TicketID}

    if ($Version)
    {$_requestBody["Version"] = $Version}

    if ($ActionType)
    {$_requestBody["ActionType"] = $ActionType}

    if ($isUse)
    {$_requestBody["isUse"] = $isUse}

    if ($Machine)
    {$_requestBody["Machine"] = $Machine}

    # Build the web request options.
    $_webRequestOptions = @{
        Uri = $_requestURL
        #TimeoutSec = $RequestTimeout
        ContentType = "application/json"
        Method = "POST"
        Headers = $_requestHeaders
        Body = $_requestBody
    }

    # Submit the request.  Return all accounts in the safe that meet the search criteria.
    $_result = Invoke-PASRestMethod @_webRequestOptions

    # Return the result.
}
#endRegion CyberArk REST API:  Accounts

##########################################################
#region Flow
##########################################################
Write-Host "**********  Starting  **********"
# Build the base URL.  This joins the Base URI to the IIS Application Name.
$_baseURL = Join-Url -Path $PVWAURL -ChildPath $IISAppName
Write-Verbose ("{0} : Base URL:  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_baseURL)

##########################################################
#region Get CyberArk Authentication Token
##########################################################
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
#endRegion Get CyberArk Authentication Token
##########################################################
#region Custom Code
##########################################################
Write-Host ("{0} : Entered Custom Code Section." -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))

##########################################################
#region Choose Action
##########################################################
switch ($Action)
{
    # Credential
    "Credential"
    {
        Write-Host ("{0} : Retrieving Credential:  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Query)

        # Check if the variable Query exists and is not null.
        if (($Query) -and ($Query -ne ""))
        {
            # Get the credential from CyberArk.
            $_cred = Get-Credential -BaseURL $_baseURL -Query $Query -Authorization $_authToken

            # Choose how to output the file.  Standard Out or a file.
            if ($OutFile)
            {
                # An output file has been specified.
                # Write the Private SSH key to the file specified in OutFile.
                Write-Host ("{0} : Writing private key to:  `r`n`t{1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_privFile)
                Write-File -Path $OutFile -Data ($_cred|ConvertTo-Json|ConvertTo-SecureString -AsPlainText -Force)
            }
            else
            {
                # No output file was specified.  Return the credential object.
                Write-Host ("{0} : Returning credential object for:  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_cred.Username)
                return $_cred
            }
        }
        else 
        {
            # Query is missing or blank
            Stop-Exit -Code 5000 -Message "A valid query is needed when the action of Credential is specified."
        }
    }

    # MFA Caching
    "MFACache"
    {
        Write-Host ("{0} : Retrieving MFA Caching SSH key." -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
        # Check if the variable OutFile exists and is not null.
        if (($OutFile) -and ($OutFile -ne ""))
        {
            # Get the extension of the given OutFile.
            $_ofPath = [System.IO.Path]::GetDirectoryName($OutFile)
            $_ofFileName = [System.IO.Path]::GetFileNameWithoutExtension($OutFile)
            $_ofExtension = ([System.IO.Path]::GetExtension($OutFile))

            # Strip the period from the extension.
            $_ofExtension = $_ofExtension.Replace('.', '')

            # Check the file format.  It needs to be PPK, PEM, or OpenSSH
            if (($_ofExtension -ieq "PPK") -or ($_ofExtension -ieq "PEM") -or ($_ofExtension -ieq "OpenSSH"))
            {
                # Generate and download the MFA caching SSH key.
                $_mcKey = Get-MFACaching -BaseURL $_baseURL -Authorization $_authToken -Format $_ofExtension

                # Write out the meta information.
                Write-Host ("{0} : Creation Time  :  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), ($UNIXORIGIN.AddSeconds($_mcKey.creationTime)))
                Write-Host ("{0} : Expiration Time:  {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), ($UNIXORIGIN.AddSeconds($_mcKey.expirationTime)))

                # Get the keys in the value.
                $_htKeys = $_mcKey.Value

                # Loop over the keys.
                foreach ($_key in $_htKeys)
                {
                    # Create the filenames.
                    if ($_ofPath)
                    {
                        $_privFile = Join-Path -Path $_ofPath -ChildPath ("{0}_{1}_private.{2}" -f $_ofFileName, $_key.keyAlg, $_key.format)
                        $_pubFile = Join-Path -Path $_ofPath -ChildPath ("{0}_{1}_public.{2}" -f $_ofFileName, $_key.keyAlg, $_key.format)
                    }
                    else
                    {
                        $_privFile = ("{0}_{1}_private.{2}" -f $_ofFileName, $_key.keyAlg, $_key.format)
                        $_pubFile = ("{0}_{1}_public.{2}" -f $_ofFileName, $_key.keyAlg, $_key.format)
                    }
                    
                    # Write the Private SSH key to the file specified in OutFile.
                    Write-Host ("{0} : Writing private key to:  `r`n`t{1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_privFile)
                    Write-File -Path $_privFile -Data $_key.privateKey

                    # Write the Public SSH key to the file specified in OutFile.
                    Write-Host ("{0} : Writing public key:  `r`n`t{1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_pubFile)
                    Write-File -Path $_pubFile -Data $_mcKey.publicKey
                }
                
            }
            else
            {
                Stop-Exit -Code 5002 -Message ("The format of the OutFile is invalid.  Valid (PPK, PEM, OpenSSH).  Given ({0})" -f $_ofExtension)
            }
        }
        else
        {
            # OutFile is missing or blank
            Stop-Exit -Code 5001 -Message "A valid OutFile is needed when the action of MFACache is specified."
        }
    }

    # Default.  If an invalid action is passed.
    default
    {
        Stop-Exit -Code 5010 -Message ("Invalid Action Specified!  Valid Actions:  MFACach, Credential.  Given ({0})" -f $Action)
    }
}

#endRegion Choose Action

#endRegion Custom Code

##########################################################
#region Logoff
##########################################################
Write-Host ("{0} : Entered Logoff Section." -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
# Test if there is an authentication token.
if ($_authToken)
{
    $_revokeAuthToken = @{
        TargetURL = $_baseURL
        AuthToken = $_authToken
        RequestTimeout = $RequestTimeout
    }
    $_result = Revoke-AuthToken @_revokeAuthToken
}
#endRegion Logoff
Write-Host "**********  Finished  **********"
#endRegion Flow