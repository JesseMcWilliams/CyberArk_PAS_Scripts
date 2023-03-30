<#
#>
# Setup any Using statements.
Using Module Logger

# Specify the input parameters.
[cmdletbinding()]
    Param(
        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [string] $ConfigFile = "\Conf\Development.xml",

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [ValidateSet("None","Critical","Error","Warning","Information","Debug","Verbose","Trace")]
        [string] $LogLevel = "Verbose",

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [switch] $EnableDebug,

        [parameter(
            Mandatory = $false,
            ValueFromPipeline = $true
        )]
        [switch] $EnableVerbose
    )

# Import any needed modules.
Import-Module ".\Modules\Configuration.psm1" -Force
Import-Module ".\Modules\Credential.psm1" -Force
Import-Module ".\Modules\CyberArk_Driver_REST.psm1" -Force
Import-Module ".\Modules\CustomWebRequest.psm1" -Force
Import-Module ".\Modules\PS_Script_Utilities.psm1" -Force

#region PowerShell Debug/Verbose output
# Valid settings:  SilentlyContinue, Continue,

# Enable Debug.  By default $DebugPreference is SilentlyContinue.
#$DebugPreference = Continue
if ($EnableDebug)
{
    $DebugPreference = Continue
}

# Enable Verbose.  By default $VerbosePreference is SilentlyContinue.
#$VerbosePreference = Continue
if ($EnableVerbose)
{
    $DebugPreference = Continue
    $VerbosePreference = Continue
    $EnableDebug = $true
}

#endregion PowerShell Debug/Verbose output
#region Get Script Variables
# Setup the logging object and set the current logging level.
#  This is a custom logging module to allow easier log ouput to console or file.
$Logger = [Logger]::new($LogLevel)

# Get the current folder.  This is the current working folder.
$_currentPath = (Get-Location).Path

# Get the script folder.  This is the folder where the script lives.
$_scriptPath = $PSScriptRoot

# Get the start time.
$_startDateTime = Get-Date

#endregion Get Script Variable

#region Functions



#endregion Functions

#region Flow
#region This Region Should NOT need to be modified.
#Write-Host ("******************** {0} : {1} ********************" -f $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"), "Starting")
$Logger.Write(("******************** {0} ********************" -f "Starting"), "Information")

# Get the configuration information from the specified XML file.
$Logger.Write(("Getting Configuration Information from :  {0}" -f $ConfigFile), "Information")
$_xmlDoc = Read-Configuration -Path $ConfigFile

# Get the Configuration element from the XML document.
$_Configuration = $_xmlDoc.Configuration

#region Configure Logging
# Check to see if any logging inforamtion was specified.
if ($_Configuration.Logging)
{
    $Logger.Write(("Setting new Logging properties :  {0}" -f $_Configuration.Logging), "Debug")

    # Setup the logging attributes.
    $null = Set-Logging -LoggingConfig $_Configuration.Logging -LogObject $Logger

    $Logger.Write(("******************** {0} ********************" -f "Starting"), "Information", "File")
    $Logger.Write(("********* Started at {0} *********" -f $_startDateTime.ToString("yyyy-MM-dd HH:mm:ss")), "Information", "File")
}
else
{
    $Logger.Write(("No Logging properties to set." ), "Information")
}
#endregion Configure Logging

$EnableDebug = $true
# Check to see if Debugging was requested and do some debug testing and output.
if ($EnableDebug)
{
    # Check configuration attributes.
    $Logger.Write(("Checking All Configuration Attributes  :  {0}" -f $ConfigFile), "Debug")
    $_stringConfigAttributes = Test-Configuration -ConfigFile $ConfigFile -XMLConfiguration $_xmlDoc
    $Logger.Write(("      Sorted Configuration Attributes  :  `r`n{0}" -f $_stringConfigAttributes), "Debug")
}

#region Initial Session Setup and Credential retrieval.
# Build the base URI for the PVWA.
$Logger.Write(("Setting PVWA URI properties :  {0}" -f $_Configuration.PVWAInformation.Address), "Debug")
$_pvwaProperties = @{
    Schema = $_Configuration.PVWAInformation.Schema
    Address = $_Configuration.PVWAInformation.Address
    Port = $_Configuration.PVWAInformation.Port
    Path = $_Configuration.PVWAInformation.BasePath
}
$_PVWAURI = Get-NewURI @_pvwaProperties

$Logger.Write(("              New PVWA URI  :  {0}" -f $_PVWAURI), "Debug")

# Get the First Credential Request object.
$_CredReqStage = 1

$Logger.Write(("  Getting Credential Request:  {0}" -f $_CredReqStage), "Debug")

# Build request attributes for getting the credential request.
$_reqNewCredReqProperties = @{
    AuthSourceAttributes = $_Configuration.AuthSourceAttributes
    PVWAAuthentication = $_Configuration.PVWAAuthentication
    Stage = $_CredReqStage
}
$_firstCredentialRequest = New-CredentialRequest @_reqNewCredReqProperties

$Logger.Write(("      New Credential Request:  `r`n`t{0}" -f ($_firstCredentialRequest | ConvertTo-Json).Replace("`n", "`n`t")), "Debug")

# Get the First Credential object.
$Logger.Write(("  Getting First Credential From:  {0}" -f $_firstCredentialRequest["Source"]), "Debug")

#  Build the request attributes for getting the credential.
$_reqFirstCredentialAttributes = @{
    Method = $_firstCredentialRequest["Method"]
    Source = $_firstCredentialRequest["Source"]
    Query  = $_firstCredentialRequest["Query"]
}
$_firstCredential = Get-SessionCredential @_reqFirstCredentialAttributes

$Logger.Write(("  First Credential Retrieved:  {0}" -f $_firstCredential["Credential"].UserName), "Debug")

#endregion Initial Session Setup and Credential retrieval.
#endregion This Region Should NOT need to be modified.

# Test if the first credential was retrieved.
if (($_firstCredential) -and (Test-Credential -Credential $_firstCredential["Credential"]))
{
    # Get the PVWA REST API Authentication Token for use with the Authorization header.
    $Logger.Write(("********** Logging On As ({0}) **********" -f $_firstCredential["Credential"].UserName), "Information")
    $_firstSessionAttributes = @{
        BaseURI = $_PVWAURI
        AuthType = $_firstCredential["Method"]
        Credential = $_firstCredential["Credential"]
        IgnoreSSL = $_Configuration.PVWAInformation.IgnoreSSL
    }
    $firstSessionToken = Get-SessionToken @_firstSessionAttributes

    # Verify that a valid session token was retrieved.
    if (Test-SessionToken -Token $firstSessionToken)
    {
        # Get the Second Credential if requested.
        if ($_Configuration.PVWAAuthentication.NumStages -eq 2)
        {
            # Get the Second Credential
            $_secondCredential = ""

            # Get the second Session Token

            # Logoff first Session Token.
        }
        else
        {
            $activeSessionToken = $firstSessionToken
        }

        #region Do the work.
        # ******************************************************************************************** #
        $Logger.Write(("********** Starting Requested Actions After Logon. **********" ), "Information")
        # ******************************************************************************************** #

        #$result = Get-VaultName -BaseURI $_PVWAURI -SessionToken $activeSessionToken
        #$Logger.Write(("  Vault Server Version  :  {0}" -f $result), "Debug")

        #$result = Get-VaultInfo -BaseURI $_PVWAURI -SessionToken $activeSessionToken
        #$Logger.Write(("Vault Server Information:  {0}" -f $result), "Debug")

        # ******************************************************************************************** #
        $Logger.Write(("********** Finished Requested Actions After Logon. **********" ), "Information")
        # ******************************************************************************************** #
        #endregion Do the work.

        # Log Off.
        $Logger.Write(("********** Logging Off **********" ), "Information")

        # Set the session parameters for Log off / Clear the session token.
        $logoffParameters = @{
            BaseURI = $_PVWAURI
            AuthType = $_firstCredential["Method"]
            SessionToken = $firstSessionToken
        }
        $logoffResults = Clear-SessionToken @logoffParameters
    }
    else
    {
        $Logger.Write(("Unable to get the First Session Token.  Stopping!" ), "Warning")
    }
}
else
{
    $Logger.Write(("Unable to get the First Credential.  Stopping!" ), "Warning")
}


$Logger.Write(("******************** {0} ********************" -f "Finished"), "Information")
#Write-Host ("******************** {0} : {1} ********************" -f $(Get-Date -Format "yyyy-MM-dd HH:mm:ss"), "Finished")
#endregion Flow
