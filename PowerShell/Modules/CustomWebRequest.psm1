<#
#>
Import-Module ".\Modules\PS_Script_Utilities.psm1" -Force
#region Web Request Functions
function Invoke-CustomWebRequest
{
    [cmdletbinding(DefaultParameterSetName = 'WebSession')]
    Param(
        [parameter(
            Mandatory = $false
        )]
        [string] $URI,

        [parameter(
            Mandatory = $false
        )]
        [ValidateSet("Delete","Get","Head","Merge","Options","Patch","Post","Post","Put","Trace","Default")]
        [string] $Method,

        [parameter(
            Mandatory = $false
        )]
        [ValidateSet("None","Basic","Bearer","OAuth")]
        [string] $Authentication,

        [parameter(
            Mandatory = $false
        )]
        [hashtable] $Headers,

        [parameter(
            Mandatory = $false
        )]
        [object] $Body,

        [parameter(
            Mandatory = $false
        )]
        [string] $ContentType = "application/json",

        [parameter(
            Mandatory = $false
        )]
        [pscredential] $Credential,

        [parameter(
            Mandatory = $false
        )]
        [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,

        [parameter(
            Mandatory = $false
        )]
        [switch] $EnableDebug,

        [parameter(
            Mandatory = $false,
            ParameterSetName = 'SessionVariable'
        )]
        [string] $SessionVariable,

        [parameter(
            Mandatory = $false,
            ParameterSetName = 'WebSession'
        )]
        [Microsoft.PowerShell.Commands.WebRequestSession] $WebSession,

        [Parameter(
            Mandatory = $false
        )]
		[bool] $SkipCertificateCheck = $false
    )

    Begin
    {
        # Force Debug
        $EnableDebug = $True

        # Check if a body is being passed in.
        if ($Body)
        {
            # Get the Body Hash Table and convert it to a JSON string.
            $_jsonBody = ConvertTo-Json $Body

            # Update Body to the JSON Body
            $PSBoundParameters["Body"] = $_jsonBody
        }

        # Check if Certificate Errors should be ignored.
        Switch ($PSBoundParameters.ContainsKey('SkipCertificateCheck')) {

			$true 
            {
				#SkipCertificateCheck Declared
                Write-Warning ("{0} |    Warning  | Skipping Certificate Validation" -f $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
                
				if ( -not (Test-IsCoreCLR)) {

					# Check for the PowerShell Version.
                    if ($PSVersionTable.PSVersion.Major -ge 6)
                    {
                        # Version 6.0.0 and higher have the Skip Certificate Check parameter.
                    }
                    else
                    {
                        #Remove parameter, incompatible with PowerShell
                        $PSBoundParameters.Remove('SkipCertificateCheck') | Out-Null

                        if ($SkipCertificateCheck) 
                        {
                            #Skip SSL Validation
                            $null = Skip-CertificateCheck
                        }
                    }

				} else {

					#PWSH
					if ($SkipCertificateCheck) 
                    {
						#Ongoing SSL Validation Bypass Required
						$Script:SkipCertificateCheck = $true
					}
				}
			}

			$false 
            {

				#SkipCertificateCheck Not Declared
				#SSL Validation Bypass Previously Requested
				If ($Script:SkipCertificateCheck) 
                {
					#PWSH Zone
					if (Test-IsCoreCLR)
                    {

						#Add SkipCertificateCheck to PS Core command
						#Parameter must be included for all pwsh invocations of Invoke-WebRequest
						$PSBoundParameters.Add('SkipCertificateCheck', $true)
					}
				}
			}
		}


    }
    Process
    {
        # Write debug output if requested
        if ($EnableDebug)
        {
            # Debug has been requested.  Get data to output.
            #  Make a deep copy of the PSBoundParameters.
            $_debugPSBoundParameters = Copy-HashTable -InputObject $PSBoundParameters

            # Check if a certificate is being passed in.
            if ($Certificate)
            {
                # Get the Certificate attributes we want to display.
                $_maskedCertificate = Get-CertificateAttributes -InputObject $Certificate

                # Update the certificate attribute.
                $_debugPSBoundParameters.Certificate = $_maskedCertificate
            }

            # If Debug is enabled get a masked Body.
            if ($Body)
            {
                # Get a masked body so we don't expose any passwords.
                $_maskedBody = Get-MaskedBody -Body $Body

                # Update the certificate attribute.
                $_debugPSBoundParameters.Body = $_maskedBody
            }

            # Write the debug information to console.
            Write-Host ("{0} |      Debug  | Web Request Properties:  `r`n`t{1}" -f $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"), (ConvertTo-Json -InputObject $_debugPSBoundParameters).Replace("`n", "`n`t"))
        }


        try
        {
            # Make the request.
            $_restResponse = Invoke-WebRequest @PSBoundParameters -ErrorAction Stop

            # Build the return object for Success.
            $_retObject = @{
                StatusCode = $_restResponse.StatusCode
                StatusDescription = $_restResponse.StatusDescription
                StatusMessage = $_restResponse.StatusMessage
                WebSession = $CurrentWebSession
                Body = $_restResponse
                ErrorDetails = @{}
            }
        }
        catch [System.Net.WebException]
        {
            # Build an object to hold the error details
            $_errorDetails = @{}

            # Grab the current error object
            $_currentException = $PSItem

            # Get the response details
            $_errorDetails["StatusCode"] = [int]$_currentException.Exception.Response.StatusCode
            $_errorDetails["StatusDescription"] = $_currentException.Exception.Response.StatusDescription
            $_errorDetails["RecommendedAction"] = $_currentException.ErrorDetails.RecommendedAction
            $_errorDetails["ExceptionMessage"] = $_currentException.Exception.Message
            $_errorDetailsMessage = $_currentException.ErrorDetails.Message

            # Check if Error Details Message exists.
            if ($_errorDetailsMessage)
            {
                # Check if it is formated as JSON and convert if it is.
                #  We do this by checking for curly brackets at the front and end.
                $_edmFChar = $_errorDetailsMessage.SubString(0,1)
                $_edmLChar = $_errorDetailsMessage.SubString(($_errorDetailsMessage.Length - 1),1)
                if (($_edmFChar -ieq "{") -and ($_edmLChar -ieq "}"))
                {
                    $_errorDetails["ErrorDetailsMessage"] = ConvertFrom-Json -InputObject $_errorDetailsMessage
                }
                else
                {
                    # Split the string on CR/LF and assign to variables.
                    $_edmStringArr = $_errorDetailsMessage.Split("`r`n")

                    # Setup the error details JSON object.
                    $_errorDetailsJSON = [PSCustomObject]@{
                        ErrorCode = $_edmStringArr[2]
                        ErrorMessage = $_edmStringArr[4]
                    }
                    $_errorDetails["ErrorDetailsMessage"] = $_errorDetailsJSON
                }
            }

            # Get the request details from the Target Object if it exists.
            if ($_currentException.TargetObject)
            {
                $_errorDetails["RequestURI"] = $_currentException.TargetObject.Address
                $_errorDetails["RequestMethod"] = $_currentException.TargetObject.Method
                $_errorDetails["RequestHeaders"] = $_currentException.TargetObject.Headers.ToString()
            }

            # Output the details
            Write-Warning ("{0} | Warning |    Status Code    :  {1}" -f  $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_errorDetails["StatusCode"])
            Write-Warning ("{0} | Warning | Status Description:  {1}" -f  $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_errorDetails["StatusDescription"])
            Write-Warning ("{0} | Warning | Error Details Code:  {1}" -f  $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_errorDetails["ErrorDetailsMessage"].ErrorCode)
            Write-Warning ("{0} | Warning | Error Details Desc:  {1}" -f  $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_errorDetails["ErrorDetailsMessage"].ErrorMessage)
            Write-Warning ("{0} | Warning | Recommended Action:  {1}" -f  $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_errorDetails["RecommendedAction"])
            Write-Warning ("{0} | Warning |  Error Message    :  {1}" -f  $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_errorDetails["ExceptionMessage"])



            # Build the return object for Errors.
            $_retObject = @{
                StatusCode = $_statusCode
                StatusDescription = $_statusDescription
                StatusMessage = $_errorMessage
                WebSession = $CurrentWebSession
                Body = $_restResponse
                ErrorDetails = $_errorDetails
            }
        }
        catch
        {
            # Build an object to hold the error details
            $_errorDetails = @{}

            # Grab the current error object
            $_currentException = $PSItem

            Write-Warning ("{0} | Warning | Web Request Type  :  {1}" -f $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_currentException.GetType())
            Write-Warning ("{0} | Warning | Web Request Failed:  {1}" -f $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_currentException.Exception.Message)
        }
        finally
        {
            #
        }

    }
    End
    {
        return $_retObject
    }
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

#endregion Web Request Functions
