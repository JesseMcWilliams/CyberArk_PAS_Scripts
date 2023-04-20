<#
#>
Import-Module ".\Modules\PS_Script_Utilities.psm1" -Force

#region Build Credential Request
function New-CredentialRequest
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [System.Xml.XmlElement] $AuthSourceAttributes,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [System.Xml.XmlElement] $Authentication,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [int] $Stage
    )

    # Set the attribute name for the requested authentication method.  Add the stage number.
    $_reqMethodAttribName = ("Method{0}" -f $Stage)

    # Get the requested authentication method.
    $_reqAuthMethodName = $Authentication.$_reqMethodAttribName

    # Set the attribute name for the requested authentication source.  Add the stage number.
    $_reqSourceAttribName = ("Source{0}" -f $Stage)

    # Get the requested authentication source.
    $_reqAuthSourceName = $Authentication.$_reqSourceAttribName

    # Build the request body object.
    $_reqBody = @{}

    # Build the request body for the Source.
    #  Choose the body based on the requested source.  Switch is case insensitive.
    switch ($_reqAuthSourceName)
    {
        "Prompt"
        {
            # Add the required attributes to the request body.
            $_reqBody["Method"] = $_reqAuthMethodName
            $_reqBody["Source"] = $_reqAuthSourceName
            $_reqBody["Query"] = @{
                CustomPromptEnabled = Get-BoolFromString -Text $AuthSourceAttributes.CustomPromptEnabled
                CustomPromptTitle = $AuthSourceAttributes.CustomPromptTitle
            }
        }
        "LocalFile"
        {
            # Add the required attributes to the request body.
            $_reqBody["Method"] = $_reqAuthMethodName
            $_reqBody["Source"] = $_reqAuthSourceName
            $_reqBody["Query"] = @{
                Path = $AuthSourceAttributes.FilePath
                Attributes = ""
            }
        }
        "CredFile"
        {
            # Add the required attributes to the request body.
            $_reqBody["Method"] = $_reqAuthMethodName
            $_reqBody["Source"] = $_reqAuthSourceName
            $_reqBody["Query"] = @{
                Path = $AuthSourceAttributes.FilePath
                Attributes = ""
            }
        }
        "AAM"
        {
            # Add the required attributes to the request body.
            $_reqBody["Method"] = $_reqAuthMethodName
            $_reqBody["Source"] = $_reqAuthSourceName
            $_reqBody["Query"] = @{
                Path = $AuthSourceAttributes.FilePath
                AppID = $AuthSourceAttributes.CredentialRetrieval.ApplicationID
                Safe = $AuthSourceAttributes.CredentialRetrieval.SafeName
                Folder = $AuthSourceAttributes.CredentialRetrieval.FolderName
                Query = $AuthSourceAttributes.CredentialRetrieval.Query
                Reason = $AuthSourceAttributes.CredentialRetrieval.RetrievalReason
            }
        }
        "CCP"
        {
            # Add the required attributes to the request body.
            $_reqBody["Method"] = $_reqAuthMethodName
            $_reqBody["Source"] = $_reqAuthSourceName
            $_reqBody["Query"] = @{
                Address = $AuthSourceAttributes.CredentialRetrieval.CCP.Address
                BasePath = $AuthSourceAttributes.CredentialRetrieval.CCP.BasePath
                Port = $AuthSourceAttributes.CredentialRetrieval.CCP.Port
                Schema = $AuthSourceAttributes.CredentialRetrieval.CCP.Schema
                IgnoreSSL = Get-BoolFromString -Text $AuthSourceAttributes.CredentialRetrieval.CCP.IgnoreSSL
                Credential = @{
                    Path = $AuthSourceAttributes.CredentialRetrieval.CCP.CertPath
                    Attributes = $AuthSourceAttributes.CredentialRetrieval.CCP.CertAttributes
                }
                AppID = $AuthSourceAttributes.CredentialRetrieval.ApplicationID
                Safe = $AuthSourceAttributes.CredentialRetrieval.SafeName
                Folder = $AuthSourceAttributes.CredentialRetrieval.FolderName
                Query = $AuthSourceAttributes.CredentialRetrieval.Query
                Reason = $AuthSourceAttributes.CredentialRetrieval.RetrievalReason
            }
        }
        "RESTAPI"
        {
            # Add the required attributes to the request body.
            $_reqBody["Method"] = $_reqAuthMethodName
            $_reqBody["Source"] = $_reqAuthSourceName
            $_reqBody["Query"] = @{
                Address = $AuthSourceAttributes.CredentialRetrieval.CCP.Address
                BasePath = $AuthSourceAttributes.CredentialRetrieval.CCP.BasePath
                Port = $AuthSourceAttributes.CredentialRetrieval.CCP.Port
                Schema = $AuthSourceAttributes.CredentialRetrieval.CCP.Schema
                IgnoreSSL =  Get-BoolFromString -Text $AuthSourceAttributes.CredentialRetrieval.CCP.IgnoreSSL
                Credential = @{
                    Path = $AuthSourceAttributes.CredentialRetrieval.CCP.CertPath
                    Attributes = $AuthSourceAttributes.CredentialRetrieval.CCP.CertAttributes
                }
                AppID = $AuthSourceAttributes.CredentialRetrieval.ApplicationID
                Safe = $AuthSourceAttributes.CredentialRetrieval.SafeName
                Folder = $AuthSourceAttributes.CredentialRetrieval.FolderName
                Query = $AuthSourceAttributes.CredentialRetrieval.Query
                Reason = $AuthSourceAttributes.CredentialRetrieval.RetrievalReason
            }
        }
        "PKI"
        {
            # Add the required attributes to the request body.
            $_reqBody["Method"] = $_reqAuthMethodName
            $_reqBody["Source"] = $_reqAuthSourceName
            $_reqBody["Query"] = @{
                Credential = @{
                    Path = $AuthSourceAttributes.PKIPath
                    Attributes = $AuthSourceAttributes.PKIAttributes
                }
            }
        }
    }

    # Write Verbose information.
    Write-Verbose ("{0} | Verbose | Requested Authentication Method:  {1}({2})" -f $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_reqMethodAttribName, $_reqAuthMethodName)
    Write-Verbose ("{0} | Verbose | Requested Authentication Source:  {1}({2})" -f $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $_reqSourceAttribName, $_reqAuthSourceName)

    return $_reqBody
}

#endregion Build Credential Request
#region Retrieve Credential
# Create a hash table of the Credential Sources.
$_authorizedCredentialSources = @{
    Prompt      = "A Windows GUI will ask for the needed information."
    AAM         = "A request to the locally installed Credential Provider will be made."
    CCP         = "A request to the Central Credential Provider will be made."
    RESTAPI     = "A request to the PVWA Management REST API will be made."
    LocalFile   = "A local file with encrypted data will be read."
    CredFile    = "A local file created with the CyberArk CreateCredFile utility."
    PKI         = "A local Certificate with Client Authentication and Private Key will be used."
}
function Get-SessionCredential
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string] $Method,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [ValidateScript({
            if (-not ($_authorizedCredentialSources.Keys -contains $PSItem))
            {return $false}
            else {return $true}
        })]
        [string] $Source,

        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [hashtable] $Query
    )

    # Choose the action
    switch ($Source)
    {
        "Prompt"
        {
            # Function Properties
            #  Check if a custom prompt is enabled.
            if ($Query["CustomPromptEnabled"])
            {
                # Custom Prompt is NOT Enabled.
                $_functionProperties = @{
                    CustomMessagePrompt = $Query["CustomPromptTitle"]
                }
            }
            else
            {
                $_functionProperties = @{
                    CustomMessagePrompt = ""
                }
            }

            Write-Debug ("{0} | Getting Credential From ({1}) | Using Attributes `r`n`t{2}" -f $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Source, ($_functionProperties | ConvertTo-Json).Replace("`n", "`n`t"))

            $sessionCredential = Get-CredentialPrompt @_functionProperties
        }

        "AAM"
        {
            # Function Properties
            $_functionProperties = @{
                ApplicationID = $ApplicationID
                SafeName = $SafeName
                Query = $Query
                Reason = $Reason
                AAMClientPath = $Path
            }

            Write-Debug ("{0} | Getting Credential From ({1}) | Using Attributes `r`n`t{2}" -f $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Source, ($_functionProperties | ConvertTo-Json).Replace("`n", "`n`t"))

            $sessionCredential = Get-CredentialAAM @_functionProperties
        }

        "CCP"
        {
            # Function Properties
            $_functionProperties = @{
                ApplicationID = $ApplicationID
                SafeName = $SafeName
                Query = $Query
                Reason = $Reason
                URL = $URL
                SkipCertificateChecking = $SkipCertificateChecking
            }

            Write-Debug ("{0} | Getting Credential From ({1}) | Using Attributes `r`n`t{2}" -f $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Source, ($_functionProperties | ConvertTo-Json).Replace("`n", "`n`t"))

            $sessionCredential = Get-CredentialCCP @_functionProperties
        }

        "RESTAPI"
        {
            # Function Properties
            $_functionProperties = @{
                ApplicationID = $ApplicationID
                SafeName = $SafeName
                Query = $Query
                Reason = $Reason
                URL = $URL
                SkipCertificateChecking = $SkipCertificateChecking
            }

            Write-Debug ("{0} | Getting Credential From ({1}) | Using Attributes `r`n`t{2}" -f $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Source, ($_functionProperties | ConvertTo-Json).Replace("`n", "`n`t"))

            $sessionCredential = Get-CredentialREST @_functionProperties
        }

        "LocalFile"
        {
            # Function Properties
            $_functionProperties = @{
                FileLocation = $Query["Path"]
            }

            Write-Debug ("{0} | Getting Credential From ({1}) | Using Attributes `r`n`t{2}" -f $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Source, ($_functionProperties | ConvertTo-Json).Replace("`n", "`n`t"))

            $sessionCredential = Get-CredentialFile @_functionProperties
        }

        "CredFile"
        {
            # Function Properties
            $_functionProperties = @{
                FileLocation = $Query["Path"]
            }

            Write-Debug ("{0} | Getting Credential From ({1}) | Using Attributes `r`n`t{2}" -f $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Source, ($_functionProperties | ConvertTo-Json).Replace("`n", "`n`t"))

            $sessionCredential = Get-CyberArkCredFile @_functionProperties
        }

        "PKI"
        {
            # Function Properties
            $_functionProperties = @{
                CertificateAttributes = $Query["Credential"]["Attributes"]
                CertificatePath = $Query["Credential"]["Path"]
            }

            Write-Debug ("{0} | Getting Credential From ({1}) | Using Attributes `r`n`t{2}" -f $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Source, ($_functionProperties | ConvertTo-Json).Replace("`n", "`n`t"))

            $sessionCredential = Get-CredentialPKI @_functionProperties
        }
    }

    # Build the object to return.
    $_retCredObject = @{
        Source = $Source
        Method = $Method
        Credential = $sessionCredential
    }
    return $_retCredObject
}
function Get-CredentialPrompt
{
    [cmdletbinding()]
    Param(
        [parameter(
                Mandatory = $false,
                ValueFromPipeline = $true
            )]
            [AllowEmptyString()]
            [string] $CustomMessagePrompt
    )
    # Prompt for the credential.
    if ($CustomMessagePrompt -and $CustomMessagePrompt -ne "")
    {
        return Get-Credential -Message $CustomMessagePrompt
    }
    else
    {
        return Get-Credential
    }
}
function Get-CredentialAAM
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string] $ApplicationID,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string] $SafeName,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string] $Query,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string] $Reason,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string] $AAMClientPath
    )

    # Build the command parameters using string formating
    $_commandParameters = ('/p AppDescs.AppID={0} /p RequiredProps=UserName,Address /p Query="Safe={1};Folder=Root;{2}" /o PassProps.UserName,PassProps.Address,Password,PasswordChangeInProcess' -f $ApplicationID, $SafeName, $Query)

    # Call the function to make the call to the AAM/AIM SDK.

    # Break out the results to get the credential properties.
    $_stdOut = $_result[1]
    $_accountAttributes = $_stdOut.StdOut.Split(',')
    $_username = $_accountAttributes[0]
    $_address = $_accountAttributes[1]
    $_content = $_accountAttributes[2]
    $_inChange = $_accountAttributes[3]

    # Convert the content into a secure string
    $_password = ConvertTo-SecureString $_content -AsPlainText -Force

    # Return the credential object.
    return New-Object System.Management.Automation.PSCredential ($_username, $_password)
}
function Get-CredentialCCP
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string] $ApplicationID,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string] $SafeName,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string] $Query,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string] $Reason,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string] $URL,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [bool] $SkipCertificateChecking = $false
    )
}
function Get-CredentialREST
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string] $SafeName,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string] $Query,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string] $Reason,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string] $URL,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [bool] $SkipCertificateChecking = $false
    )
}
function Get-CredentialFile
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string] $FileLocation
    )

    <#
        The local authentication file is created by using the ConvertFrom-SecureString and ConvertTo-SecureString
        PowerShell functions.
        https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertfrom-securestring?view=powershell-7.3
        https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring?view=powershell-7.3

        Read-Host -AsSecureString -Prompt "Username:  " | ConvertFrom-SecureString | Add-Content -Path _encryptedCred.cred
        Read-Host -AsSecureString -Prompt "Password:  " | ConvertFrom-SecureString | Add-Content -Path _encryptedCred.cred
    #>

    # Use a try catch.
    try
    {
        # Read the specified file.
        $_credentialFile = Get-Content -Path $FileLocation

        # Decrypt the username which should be the first line.
        $_username = [System.Net.NetworkCredential]::New("", (ConvertTo-SecureString $_credentialFile[0])).Password

        # Retrieve the password which should be the second line.
        $_password = ConvertTo-SecureString $_credentialFile[1]

        # Create the PowerShell Credential object and return.
        return New-Object System.Management.Automation.PSCredential ($_username, $_password)
    }
    catch
    {
        # Grab the current error object
        $_currentException = $PSItem

        Write-Warning ("{0} | Failure with File:  {1}" -f $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $FileLocation)

        # Return a bad Credential
        return [System.Management.Automation.PSCredential]::Empty
    }

}
function Get-CyberArkCredFile
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string] $FileLocation
    )

    <#
        The local CyberArk Credential file is created by running the CreateCredFile.exe utility.
        
    #>

    # Use a try catch.
    try
    {
        # Read the specified file.
        $_credentialFile = Get-Content -Path $FileLocation

        # Get the username from the credential file.
        $_labelUserName = "Username"

        # Read the file to get the username.
        $_credFileContent = Get-Content -Path $FileLocation

        # Loop over the content looking for the username label.
        foreach ($line in $_credFileContent)
        {
            if ($line.Contains($_labelUserName))
            {
                # Split the line.
                $_line = $line.Split("=")
                $_username = $_line[1]
            }
        }

        # Retrieve the password which should be the second line.
        $_password = ConvertTo-SecureString -String $FileLocation -AsPlainText -Force

        # Create the PowerShell Credential object and return.
        return New-Object System.Management.Automation.PSCredential ($_username, $_password)
    }
    catch
    {
        # Grab the current error object
        $_currentException = $PSItem

        Write-Warning ("{0} | Failure with File:  {1}" -f $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $FileLocation)

        # Return a bad Credential
        return [System.Management.Automation.PSCredential]::Empty
    }

}
function Get-CredentialPKI
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string] $CertificatePath,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string] $CertificateAttributes
    )

    # Wanted Key Usages
    $getKeyUsages = @("Client Authentication")

    # Call Get-Certificate to get a certificate.
    $_Certificate = Get-Certificate -Path $CertificatePath -FilterAttributes $CertificateAttributes.Split("|") -KeyUsages $getKeyUsages

    # Export the certificate to a byte array
    $exportedCertificate = $_Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::SerializedCert)

    # Convert the byte array to a string.
    $stringCertificate = [System.Text.Encoding]::Unicode.GetString($exportedCertificate)

    # Convert the string into a secure string.
    $secureCertificate = ConvertTo-SecureString $stringCertificate -AsPlainText -Force

    # Create the PS Credential object
    $credentialCertificate = [System.Management.Automation.PSCredential]::New("X509Certificate2", $secureCertificate)

    # Create the PowerShell Credential object and return.
    return $credentialCertificate
}
#endregion Retrieve Credential
#region Helper Functions
function Invoke-AAMClient
{
    [cmdletbinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSReviewUnusedParameter", "RemainingArgs", Justification = "Intentionally Unused Parameter")]
    Param(
        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string] $ClientPath,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string] $Command = "GetPassword",

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string] $CommandParameters,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string] $Options,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string] $RemainingArgs,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string] $SDKExecutable = "CLIPasswordSDK.exe"
    )

    # Use Begin, Process, End
    Begin
    {
        # Check if the Client Path is valid.
        if (-not (Test-Path -Path $ClientPath))
        {
            # The path doesn't exist!
            throw ("Provided path cannot be found:  {0}" -f $ClientPath)
        }
        else
        {
            # Build the full path to the SDK.
            $_fullSDKPath = Join-Path -Path $ClientPath -ChildPath $SDKExecutable

            # Check if the SDK executable exists.
            if (-not (Test-Path -Path $_fullSDKPath))
            {
                # The SDK doesn't exist!
                throw ("CLI SDK cannot be found:  {0}" -f $_fullSDKPath)
            }
            else
            {
                # Create the process object
                $_process = New-Object System.Diagnostics.Process
            }
        }
    }
    Process
    {
        if ($PSCmdlet.ShouldProcess($_fullSDKPath, "$CommandParameters"))
        {
            Write-Debug ("Command Path:  {0}" -f $_fullSDKPath)
            Write-Debug ("Command Arguments:  {0} : {1} : {2}" -f $Command, $Options, $CommandParameters)

            # Assign the process parameters
            $_process.StartInfo.WorkingDirectory = "$(Split-Path $_fullSDKPath -Parent)"
            $_process.StartInfo.FileName = $_fullSDKPath
            $_process.StartInfo.Arguments = "$Command $Options $CommandParameters"
            $_process.StartInfo.RedirectStandardOutput = $true
            $_process.StartInfo.RedirectStandardError = $true
            $_process.StartInfo.UseShellExecute = $false
            $_process.StartInfo.CreateNoWindow = $true
            $_process.StartInfo.WindowStyle = "hidden"

            # Start Process
            $_result = Start-AIMClientProcess -Process $_process -ErrorAction Stop

            # Return Error or Result
            if ($_result.StdErr -match '((?:^[A-Z]{5}[0-9]{3}[A-Z])|(?:ERROR \(\d+\)))(?::)? (.+)$')
            {
                # APPAP008E Problem occurred while trying to use user in the vault
                Write-Debug "ErrorId:  $($Matches[1])"
                Write-Debug "Message:  $($Matches[2])"
                Write-Error -Message $Matches[2] -ErrorId $Matches[1]
            }
        }
    }
    End
    {
        $_process.Dispose()

        # Return the result
        return $_result
    }
}
function Start-AIMClientProcess
{
    [cmdletbinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSShouldProcess", "", Justification = "ShouldProcess handling is in Invoke-AIMClient")]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [System.Diagnostics.Process] $Process
    )

    # Use Begin, Process, and End
    Begin
    {
        # Intentionally blank
    }
    Process
    {
        # Start the process
        $Process.start() | Out-Null

        # Read output stream
        $StdOut = $Process.StandardOutput.ReadToEnd()
        $StdErr = $Process.StandardError.ReadToEnd()

        Write-Debug "Exit Code:  $($Process.ExitCode)"

        # Create custom output object
        $toReturn = [PSCustomObject] @{
            "ExitCode" = $Process.ExitCode
            "StdOut" = $StdOut
            "StdErr" = $StdErr
        }
    }
    End
    {
        $Process.Dispose()

        # Return the result
        return $toReturn
    }

}
# Key usage OIDs
$CertificateKeyUsages = @{
    "Client Authentication" = "1.3.6.1.5.5.7.3.2"
    "Secure Email" = "1.3.6.1.5.5.7.3.4"
    "Document Signing" = "1.3.6.1.4.1.311.10.3.12"
    "Smart Card Logon" = "1.3.6.1.4.1.311.20.2.2"
}
function Get-Certificate
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string] $Path,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string[]] $FilterAttributes,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [ValidateScript({
            foreach ($entry in $PSItem)
            {
                if (-not ($CertificateKeyUsages.Keys -contains $entry))
                {return $false}
            }
            return $true
        })]
        [string[]] $KeyUsages,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [switch] $IgnoreDates,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [switch] $IgnorePrivateKey
    )

    Write-Host ("{0} | Getting Certificate from ({1}) | With Attributes ({2})" -f $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Path, ($FilterAttributes -join ","))

    # Get all certificates from the user's personal certificate store.
    $_allCerts = Get-ChildItem -Path $Path

    # Build the array to hold all of the filters to be applied.
    $_filterAttributes = [System.Collections.ArrayList]::New()

    # If any key usages were requested.  Add them as filter attributes.
    if ($KeyUsage -and ($KeyUsage.Count -gt 0))
    {
        # Loop over all requested key usages.
        foreach ($ku in $KeyUsages)
        {
            $null = $_filterAttributes.Add(("EnhancedKeyUsageList.ObjectID -contains '{0}'" -f $CertificateKeyUsages[$ku]))
        }
    }

    # Check if the certificate dates are valid.
    if (-not $IgnoreDates)
    {
        # Dates should be added to the attribute array.  Use the back tick '`' to escape the dollar sign.
        $null = $_filterAttributes.Add("NotAfter -gt (Get-Date)")
        $null = $_filterAttributes.Add("NotBefore -lt (Get-Date)")
    }

    # Check if the certificate has a private key.
    if (-not $IgnorePrivateKey)
    {
        # The certificate should have a private key.
        $null = $_filterAttributes.Add("HasPrivateKey -eq `$true")
    }

    # Check if any other filter attributes were supplied.
    if ($FilterAttributes -and ($FilterAttributes.Count -gt 0))
    {
        # Additional filter attributes have been requested.
        #  Loop over them and add to the filter.
        foreach ($fata in $FilterAttributes)
        {
            # Add the attribute
            $null = $_filterAttributes.Add($fata)
        }
    }

    # Create a string to hold the filter script block.
    $textFilterAttributes = ""

    # Loop over all filter attributes and add them to the text filter attributes.
    foreach ($fa in $_filterAttributes)
    {
        # Check if the text filter attributes is blank.  Use back tick "`" to escape the dollar sign "$".
        if ($textFilterAttributes -eq "")
        {
            # First attribute
            $textFilterAttributes = ("`t`$_.{0}" -f $fa)
        }
        else
        {
            # Not the first attribute
            $textFilterAttributes += (" -and`r`n`t`$_.{0}" -f $fa)
        }
    }

    $null = Write-Verbose ("Requested Filter Attributes:  {0}" -f ($FilterAttributes -join ", "))
    $null = Write-Verbose ("    Requested Filter Text  :  `r`n{0}" -f $textFilterAttributes)

    # Create the filter script block object
    $filterScriptBlock = [System.Management.Automation.ScriptBlock]::Create($textFilterAttributes)

    $null = Write-Verbose ("Filter Script Block:  `r`n{0}" -f $filterScriptBlock)

    # Filter the certificates.  When passing as Input Object it doesn't work.  Using pipe works.
    $filteredCerts = $_allCerts | Where-Object $filterScriptBlock

    # Any Certificates Found?
    $null = Write-Verbose ("Valid Certificates:  {0}" -f $filteredCerts.Count)

    # If more than one exists allow the user to choose.
    if ($filteredCerts.Count -gt 1)
    {
        # Add the Security module
        Add-Type -AssemblyName System.Security

        # Convert the Certificate Array into an X509Certificate2Collection
        $certCollection = [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]::New($filteredCerts)

        # Create the selection Attributes.
        $certSelectType = [System.Security.Cryptography.X509Certificates.X509SelectionFlag]::SingleSelection
        $certSelectTitle = "Valid Certificates"
        $certSelectHelp = "Select a Certificate"

        # Create the Certificate selection window.
        $certificateToReturn = [System.Security.Cryptography.X509Certificates.X509Certificate2UI]::SelectFromCollection(
            $certCollection,
            $certSelectTitle,
            $certSelectHelp,
            $certSelectType
        )
    }
    else
    {
        # Assign the certificate to the same variable as above.
        $certificateToReturn = $filteredCerts[0]
    }

    return $certificateToReturn
}
function Get-CertificateFromPSCredential
{
    # Need to pull the certificate sha1 hash from the username blob.
    # This can be done using the CredUnmarshalCredential Win32 API.
    # https://devblogs.microsoft.com/scripting/powershell-support-for-certificate-credentials/
    # https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credunmarshalcredentiala?redirectedfrom=MSDN
    # https://github.com/bongiovimatthew-microsoft/pscredentialWithCert/blob/master/SmartcardLogon/Program.cs
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [pscredential] $Credential
    )
    Write-Warning "Not Implemented!"
    return $null
    # The password in the Credential object should be the pin to unlock the private key.
    # We can't use the PIN at this time.
    # The username is the public key stored in a blob.
    # Extract the Username.
    $_username = $Credential.username
    Write-Host ("Username:  {0}" -f $_username)

    # Define the method definition to be used in Add Type.
    $MethodDefinition = @'
[DllImport("Advapi32.dll", CharSet=CharSet.Auto)]
public static extern bool CredUnmarshalCredential([in]  LPCSTR MarshalledCredential, string CredType, string Credential);
'@

    # Add the type if it doesn't already exist.  We need to use Try Catch
    try
    {
        # Write-Host (" Testing if the name space exists  :  {0}" -f "Win32.UnMarshallCred")
        # [Win32.UnMarshallCred] -is [bool]
    }
    catch
    {
        # Write-Host ("Creating the name space:  {0}" -f "Win32.UnMarshallCred")
        # $UnMarshallCred = Add-Type -MemberDefinition $MethodDefinition -Name 'UnMarshallCred' -Namespace 'Win32' -PassThru
    }


    # Call the API
    Write-Host ("Calling the unmarshal function for:  {0}" -f $_username)

    $_CredType = ""
    $_Credential = ""
    #$certSha1 = $UnMarshallCred::CredUnmarshalCredential($_username, $_CredType, $_Credential)

    Write-Host ("Cert Result:  " -f $certSha1)
    Write-Host ("Cert Type  :  " -f $_CredType)
    Write-Host ("Cert SHA 1 :  " -f $_Credential)



}
function Test-Credential
{
    [cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [pscredential] $Credential
    )

    # Test the Credential
    if ($null -ne $Credential)
    {
        if ($null -ne $Credential.UserName)
        {
            if ($Credential.UserName -ne "")
            {
                return $true
            }
        }
    }

    # Return false if we get here.
    return $false
}
#endregion Helper Functions
